// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title PlasmaPrimitives
 * @notice Core cryptographic primitives for Plasma Layer 2 scaling
 * @dev Implements UTXO model, Merkle proofs, exit games, and commitment schemes
 *
 * Plasma Architecture:
 * - Child chains anchored to Ethereum mainnet
 * - UTXO-based transaction model
 * - Merkle tree commitments for transaction inclusion
 * - Exit game for secure withdrawals with challenge periods
 * - Priority queue for exit ordering
 *
 * Key Concepts:
 * - Transaction: UTXO transfer with inputs and outputs
 * - Block: Collection of transactions with Merkle root
 * - Exit: Withdrawal from Plasma to L1 with proof
 * - Challenge: Contest invalid exits within challenge period
 */
library PlasmaPrimitives {
    // =========================================================================
    // CONSTANTS
    // =========================================================================

    /// @notice Maximum number of inputs per transaction
    uint256 public constant MAX_INPUTS = 4;

    /// @notice Maximum number of outputs per transaction
    uint256 public constant MAX_OUTPUTS = 4;

    /// @notice Merkle tree depth for transactions
    uint256 public constant MERKLE_TREE_DEPTH = 16;

    /// @notice Maximum transactions per block (2^16)
    uint256 public constant MAX_TRANSACTIONS_PER_BLOCK = 65536;

    /// @notice Challenge period duration (7 days in seconds)
    uint256 public constant CHALLENGE_PERIOD = 7 days;

    /// @notice Minimum exit bond required
    uint256 public constant MIN_EXIT_BOND = 0.1 ether;

    /// @notice Exit priority calculation base
    uint256 public constant EXIT_PRIORITY_DENOMINATOR = 10 ** 18;

    /// @notice Signature length (65 bytes: r, s, v)
    uint256 public constant SIGNATURE_LENGTH = 65;

    /// @notice Null UTXO position
    uint256 public constant NULL_UTXO_POS = 0;

    // =========================================================================
    // TYPES
    // =========================================================================

    /// @notice UTXO position encoding: blockNum * 10^9 + txIndex * 10^4 + outputIndex
    struct UTXOPosition {
        uint256 blockNum;
        uint256 txIndex;
        uint256 outputIndex;
    }

    /// @notice Transaction input referencing a UTXO
    struct TransactionInput {
        uint256 utxoPos;
        bytes signature;
    }

    /// @notice Transaction output creating a new UTXO
    struct TransactionOutput {
        address owner;
        address token;
        uint256 amount;
    }

    /// @notice Plasma transaction with inputs and outputs
    struct PlasmaTransaction {
        TransactionInput[] inputs;
        TransactionOutput[] outputs;
        bytes32 txHash;
        uint256 txIndex;
    }

    /// @notice Plasma block header
    struct PlasmaBlock {
        bytes32 root;
        uint256 timestamp;
        uint256 blockNumber;
        address operator;
        uint256 numTransactions;
    }

    /// @notice Exit data for withdrawal
    struct Exit {
        address owner;
        address token;
        uint256 amount;
        uint256 utxoPos;
        uint256 exitableAt;
        uint256 bondAmount;
        ExitStatus status;
    }

    /// @notice Exit status
    enum ExitStatus {
        NOT_STARTED,
        IN_PROGRESS,
        FINALIZED,
        CHALLENGED,
        CANCELLED
    }

    /// @notice In-flight exit for unconfirmed transactions
    struct InFlightExit {
        bytes32 txHash;
        uint256 exitStartTimestamp;
        uint256 bondOwner;
        uint256 oldestCompetitorPosition;
        bool isCanonical;
        ExitStatus status;
        TransactionOutput[] outputs;
        mapping(uint256 => bool) outputPiggybacked;
        mapping(uint256 => address) outputOwners;
    }

    /// @notice Merkle proof for transaction inclusion
    struct MerkleProof {
        bytes32[] siblings;
        uint256 index;
    }

    /// @notice Exit priority for queue ordering
    struct ExitPriority {
        uint256 exitableAt;
        uint256 utxoPos;
        uint256 exitId;
    }

    /// @notice Challenge data
    struct Challenge {
        bytes32 txHash;
        uint256 challengePosition;
        address challenger;
        uint256 timestamp;
    }

    /// @notice Cross-domain nullifier binding
    struct PlasmaNullifierBinding {
        bytes32 plasmaTxHash;
        bytes32 pilNullifier;
        bytes32 domainSeparator;
        uint256 blockNumber;
    }

    /// @notice Deposit data
    struct Deposit {
        address depositor;
        address token;
        uint256 amount;
        uint256 blockNumber;
        bytes32 commitment;
    }

    // =========================================================================
    // HASH FUNCTIONS
    // =========================================================================

    /**
     * @notice Compute keccak256 hash
     * @param data Input data
     * @return hash Keccak256 hash
     */
    function keccakHash(bytes memory data) internal pure returns (bytes32) {
        return keccak256(data);
    }

    /**
     * @notice Hash two bytes32 values
     * @param left Left value
     * @param right Right value
     * @return hash Combined hash
     */
    function hash2(
        bytes32 left,
        bytes32 right
    ) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(left, right));
    }

    /**
     * @notice Hash multiple bytes32 values
     * @param inputs Array of inputs
     * @return hash Combined hash
     */
    function hashN(bytes32[] memory inputs) internal pure returns (bytes32) {
        if (inputs.length == 0) return bytes32(0);
        if (inputs.length == 1) return inputs[0];
        return keccak256(abi.encodePacked(inputs));
    }

    // =========================================================================
    // UTXO POSITION ENCODING
    // =========================================================================

    /**
     * @notice Encode UTXO position into single uint256
     * @param blockNum Block number
     * @param txIndex Transaction index
     * @param outputIndex Output index
     * @return pos Encoded position
     */
    function encodeUTXOPosition(
        uint256 blockNum,
        uint256 txIndex,
        uint256 outputIndex
    ) internal pure returns (uint256) {
        require(outputIndex < MAX_OUTPUTS, "Output index too large");
        require(txIndex < MAX_TRANSACTIONS_PER_BLOCK, "Tx index too large");
        return blockNum * 10 ** 9 + txIndex * 10 ** 4 + outputIndex;
    }

    /**
     * @notice Decode UTXO position from uint256
     * @param pos Encoded position
     * @return blockNum Block number
     * @return txIndex Transaction index
     * @return outputIndex Output index
     */
    function decodeUTXOPosition(
        uint256 pos
    )
        internal
        pure
        returns (uint256 blockNum, uint256 txIndex, uint256 outputIndex)
    {
        blockNum = pos / 10 ** 9;
        txIndex = (pos % 10 ** 9) / 10 ** 4;
        outputIndex = pos % 10 ** 4;
    }

    /**
     * @notice Create UTXOPosition struct
     * @param pos Encoded position
     * @return position UTXOPosition struct
     */
    function toUTXOPosition(
        uint256 pos
    ) internal pure returns (UTXOPosition memory) {
        (
            uint256 blockNum,
            uint256 txIndex,
            uint256 outputIndex
        ) = decodeUTXOPosition(pos);
        return
            UTXOPosition({
                blockNum: blockNum,
                txIndex: txIndex,
                outputIndex: outputIndex
            });
    }

    /**
     * @notice Check if UTXO position is valid
     * @param pos Encoded position
     * @return valid True if valid
     */
    function isValidUTXOPosition(uint256 pos) internal pure returns (bool) {
        (
            uint256 blockNum,
            uint256 txIndex,
            uint256 outputIndex
        ) = decodeUTXOPosition(pos);
        return
            blockNum > 0 &&
            txIndex < MAX_TRANSACTIONS_PER_BLOCK &&
            outputIndex < MAX_OUTPUTS;
    }

    // =========================================================================
    // TRANSACTION HASHING
    // =========================================================================

    /**
     * @notice Compute transaction hash
     * @param inputs Input UTXOs
     * @param outputs Output UTXOs
     * @return txHash Transaction hash
     */
    function computeTransactionHash(
        TransactionInput[] memory inputs,
        TransactionOutput[] memory outputs
    ) internal pure returns (bytes32) {
        bytes memory inputsEncoded;
        for (uint256 i = 0; i < inputs.length; i++) {
            inputsEncoded = abi.encodePacked(inputsEncoded, inputs[i].utxoPos);
        }

        bytes memory outputsEncoded;
        for (uint256 i = 0; i < outputs.length; i++) {
            outputsEncoded = abi.encodePacked(
                outputsEncoded,
                outputs[i].owner,
                outputs[i].token,
                outputs[i].amount
            );
        }

        return keccak256(abi.encodePacked(inputsEncoded, outputsEncoded));
    }

    /**
     * @notice Compute typed data hash for EIP-712 signing
     * @param txHash Transaction hash
     * @param chainId Chain ID
     * @return typedHash EIP-712 typed hash
     */
    function computeTypedDataHash(
        bytes32 txHash,
        uint256 chainId
    ) internal pure returns (bytes32) {
        bytes32 domainSeparator = keccak256(
            abi.encode(
                keccak256(
                    "EIP712Domain(string name,string version,uint256 chainId)"
                ),
                keccak256("Plasma"),
                keccak256("1"),
                chainId
            )
        );

        bytes32 structHash = keccak256(
            abi.encode(keccak256("Transaction(bytes32 txHash)"), txHash)
        );

        return
            keccak256(
                abi.encodePacked("\x19\x01", domainSeparator, structHash)
            );
    }

    // =========================================================================
    // MERKLE TREE
    // =========================================================================

    /**
     * @notice Compute Merkle root from leaves
     * @param leaves Array of leaf hashes
     * @return root Merkle root
     */
    function computeMerkleRoot(
        bytes32[] memory leaves
    ) internal pure returns (bytes32) {
        if (leaves.length == 0) return bytes32(0);
        if (leaves.length == 1) return leaves[0];

        uint256 n = leaves.length;
        bytes32[] memory nodes = leaves;

        while (n > 1) {
            uint256 newN = (n + 1) / 2;
            bytes32[] memory newNodes = new bytes32[](newN);

            for (uint256 i = 0; i < newN; i++) {
                uint256 left = i * 2;
                uint256 right = left + 1;

                if (right < n) {
                    newNodes[i] = hash2(nodes[left], nodes[right]);
                } else {
                    newNodes[i] = nodes[left];
                }
            }

            nodes = newNodes;
            n = newN;
        }

        return nodes[0];
    }

    /**
     * @notice Verify Merkle proof
     * @param leaf Leaf hash
     * @param proof Merkle proof
     * @param root Expected root
     * @return valid True if proof is valid
     */
    function verifyMerkleProof(
        bytes32 leaf,
        MerkleProof memory proof,
        bytes32 root
    ) internal pure returns (bool) {
        bytes32 computed = leaf;
        uint256 index = proof.index;

        for (uint256 i = 0; i < proof.siblings.length; i++) {
            if (index % 2 == 0) {
                computed = hash2(computed, proof.siblings[i]);
            } else {
                computed = hash2(proof.siblings[i], computed);
            }
            index = index / 2;
        }

        return computed == root;
    }

    /**
     * @notice Compute Merkle root from proof
     * @param leaf Leaf hash
     * @param proof Merkle proof
     * @return root Computed root
     */
    function computeMerkleRootFromProof(
        bytes32 leaf,
        MerkleProof memory proof
    ) internal pure returns (bytes32) {
        bytes32 computed = leaf;
        uint256 index = proof.index;

        for (uint256 i = 0; i < proof.siblings.length; i++) {
            if (index % 2 == 0) {
                computed = hash2(computed, proof.siblings[i]);
            } else {
                computed = hash2(proof.siblings[i], computed);
            }
            index = index / 2;
        }

        return computed;
    }

    // =========================================================================
    // EXIT PRIORITY
    // =========================================================================

    /**
     * @notice Compute exit priority
     * @dev Lower priority exits first (FIFO within same exitableAt)
     * @param exitableAt Timestamp when exit becomes processable
     * @param utxoPos UTXO position
     * @return priority Exit priority (lower = higher priority)
     */
    function computeExitPriority(
        uint256 exitableAt,
        uint256 utxoPos
    ) internal pure returns (uint256) {
        return exitableAt * EXIT_PRIORITY_DENOMINATOR + utxoPos;
    }

    /**
     * @notice Decode exit priority
     * @param priority Encoded priority
     * @return exitableAt Timestamp
     * @return utxoPos UTXO position
     */
    function decodeExitPriority(
        uint256 priority
    ) internal pure returns (uint256 exitableAt, uint256 utxoPos) {
        exitableAt = priority / EXIT_PRIORITY_DENOMINATOR;
        utxoPos = priority % EXIT_PRIORITY_DENOMINATOR;
    }

    /**
     * @notice Compute exitable timestamp
     * @param submissionTime Exit submission timestamp
     * @return exitableAt When exit can be processed
     */
    function computeExitableAt(
        uint256 submissionTime
    ) internal pure returns (uint256) {
        return submissionTime + CHALLENGE_PERIOD;
    }

    // =========================================================================
    // SIGNATURE VERIFICATION
    // =========================================================================

    /**
     * @notice Recover signer from signature
     * @param messageHash Message hash
     * @param signature Signature bytes
     * @return signer Recovered signer address
     */
    function recoverSigner(
        bytes32 messageHash,
        bytes memory signature
    ) internal pure returns (address) {
        if (signature.length != SIGNATURE_LENGTH) return address(0);

        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }

        if (v < 27) v += 27;
        if (v != 27 && v != 28) return address(0);

        return ecrecover(messageHash, v, r, s);
    }

    /**
     * @notice Verify transaction signature
     * @param txHash Transaction hash
     * @param signature Signature
     * @param expectedSigner Expected signer
     * @return valid True if signature is valid
     */
    function verifySignature(
        bytes32 txHash,
        bytes memory signature,
        address expectedSigner
    ) internal pure returns (bool) {
        bytes32 prefixedHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", txHash)
        );
        address recovered = recoverSigner(prefixedHash, signature);
        return recovered == expectedSigner && recovered != address(0);
    }

    // =========================================================================
    // NULLIFIER DERIVATION
    // =========================================================================

    /**
     * @notice Derive nullifier from transaction
     * @param txHash Transaction hash
     * @param blockNumber Block number
     * @param outputIndex Output index
     * @return nullifier Derived nullifier
     */
    function deriveNullifier(
        bytes32 txHash,
        uint256 blockNumber,
        uint256 outputIndex
    ) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encodePacked(txHash, blockNumber, outputIndex, "PLASMA_NF")
            );
    }

    /**
     * @notice Derive cross-domain nullifier for PIL binding
     * @param plasmaNullifier Plasma nullifier
     * @param sourceChain Source chain ID
     * @param targetChain Target chain ID
     * @return crossDomainNullifier Cross-domain nullifier
     */
    function deriveCrossDomainNullifier(
        bytes32 plasmaNullifier,
        uint256 sourceChain,
        uint256 targetChain
    ) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encodePacked(
                    plasmaNullifier,
                    sourceChain,
                    targetChain,
                    "PLASMA_CROSS"
                )
            );
    }

    /**
     * @notice Derive PIL binding from Plasma nullifier
     * @param plasmaNullifier Plasma nullifier
     * @return pilBinding PIL nullifier binding
     */
    function derivePILBinding(
        bytes32 plasmaNullifier
    ) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(plasmaNullifier, "PLASMA2PIL"));
    }

    /**
     * @notice Create nullifier binding struct
     * @param txHash Transaction hash
     * @param pilNullifier PIL nullifier
     * @param blockNumber Block number
     * @return binding Nullifier binding
     */
    function createNullifierBinding(
        bytes32 txHash,
        bytes32 pilNullifier,
        uint256 blockNumber
    ) internal pure returns (PlasmaNullifierBinding memory) {
        return
            PlasmaNullifierBinding({
                plasmaTxHash: txHash,
                pilNullifier: pilNullifier,
                domainSeparator: keccak256("PLASMA_PIL_BINDING"),
                blockNumber: blockNumber
            });
    }

    // =========================================================================
    // DEPOSIT COMMITMENT
    // =========================================================================

    /**
     * @notice Compute deposit commitment
     * @param depositor Depositor address
     * @param token Token address
     * @param amount Amount
     * @param blinding Random blinding factor
     * @return commitment Deposit commitment
     */
    function computeDepositCommitment(
        address depositor,
        address token,
        uint256 amount,
        bytes32 blinding
    ) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(depositor, token, amount, blinding));
    }

    // =========================================================================
    // VALIDATION
    // =========================================================================

    /**
     * @notice Validate transaction structure
     * @param inputs Transaction inputs
     * @param outputs Transaction outputs
     * @return valid True if valid
     */
    function isValidTransaction(
        TransactionInput[] memory inputs,
        TransactionOutput[] memory outputs
    ) internal pure returns (bool) {
        if (inputs.length == 0 || inputs.length > MAX_INPUTS) return false;
        if (outputs.length == 0 || outputs.length > MAX_OUTPUTS) return false;

        // Check outputs have valid amounts
        for (uint256 i = 0; i < outputs.length; i++) {
            if (outputs[i].owner == address(0)) return false;
            if (outputs[i].amount == 0) return false;
        }

        return true;
    }

    /**
     * @notice Validate exit data
     * @param exit Exit struct
     * @return valid True if valid
     */
    function isValidExit(Exit memory exit) internal pure returns (bool) {
        if (exit.owner == address(0)) return false;
        if (exit.amount == 0) return false;
        if (exit.utxoPos == 0) return false;
        if (exit.bondAmount < MIN_EXIT_BOND) return false;
        return true;
    }

    /**
     * @notice Check if exit is finalized
     * @param exit Exit struct
     * @param currentTime Current timestamp
     * @return finalized True if finalized
     */
    function isExitFinalized(
        Exit memory exit,
        uint256 currentTime
    ) internal pure returns (bool) {
        return
            exit.status == ExitStatus.IN_PROGRESS &&
            currentTime >= exit.exitableAt;
    }

    /**
     * @notice Check if exit can be challenged
     * @param exit Exit struct
     * @param currentTime Current timestamp
     * @return challengeable True if challengeable
     */
    function isExitChallengeable(
        Exit memory exit,
        uint256 currentTime
    ) internal pure returns (bool) {
        return
            exit.status == ExitStatus.IN_PROGRESS &&
            currentTime < exit.exitableAt;
    }

    // =========================================================================
    // PLASMA CHAIN IDENTIFICATION
    // =========================================================================

    /**
     * @notice Check if chain ID is a known Plasma chain
     * @param chainId Chain ID to check
     * @return isPlasma True if Plasma chain
     */
    function isPlasmaChain(uint256 chainId) internal pure returns (bool) {
        // OMG Network (now OMG Foundation)
        if (chainId == 1) return true; // Ethereum mainnet (Plasma contracts)
        // Polygon (originally Matic Plasma)
        if (chainId == 137) return true;
        // Polygon testnet
        if (chainId == 80001) return true;

        return false;
    }

    // =========================================================================
    // BLOCK VALIDATION
    // =========================================================================

    /**
     * @notice Compute block hash
     * @param block Plasma block
     * @return blockHash Block hash
     */
    function computeBlockHash(
        PlasmaBlock memory block
    ) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encodePacked(
                    block.root,
                    block.timestamp,
                    block.blockNumber,
                    block.operator,
                    block.numTransactions
                )
            );
    }

    /**
     * @notice Validate block structure
     * @param block Plasma block
     * @return valid True if valid
     */
    function isValidBlock(
        PlasmaBlock memory block
    ) internal pure returns (bool) {
        if (block.root == bytes32(0)) return false;
        if (block.timestamp == 0) return false;
        if (block.blockNumber == 0) return false;
        if (block.operator == address(0)) return false;
        return true;
    }

    // =========================================================================
    // CHALLENGE HELPERS
    // =========================================================================

    /**
     * @notice Check if spending transaction is younger than exit
     * @param exitUtxoPos Exit UTXO position
     * @param spendingUtxoPos Spending transaction UTXO position
     * @return younger True if spending is younger
     */
    function isSpendingYounger(
        uint256 exitUtxoPos,
        uint256 spendingUtxoPos
    ) internal pure returns (bool) {
        (uint256 exitBlock, , ) = decodeUTXOPosition(exitUtxoPos);
        (uint256 spendBlock, , ) = decodeUTXOPosition(spendingUtxoPos);
        return spendBlock > exitBlock;
    }

    /**
     * @notice Compute challenge hash
     * @param exitId Exit ID
     * @param challengingTxHash Challenging transaction hash
     * @param challenger Challenger address
     * @return challengeHash Challenge hash
     */
    function computeChallengeHash(
        uint256 exitId,
        bytes32 challengingTxHash,
        address challenger
    ) internal pure returns (bytes32) {
        return
            keccak256(abi.encodePacked(exitId, challengingTxHash, challenger));
    }
}
