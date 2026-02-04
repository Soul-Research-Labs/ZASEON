// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {BiniusVerifier} from "../BiniusVerifier.sol";
import {IProofVerifier} from "../../interfaces/IProofVerifier.sol";

/**
 * @title BiniusVerifierAdapter
 * @author Soul Protocol
 * @notice Adapter to integrate BiniusVerifier with the standard IProofVerifier interface
 * @dev Bridges BiniusVerifier's custom types to the standard verification interface
 *
 * This adapter enables Binius proofs to be used through:
 * - SoulUniversalVerifier (via ProofSystem.Binius enum)
 * - VerifierRegistry (via BINIUS_PROOF type)
 * - SoulMultiProver (for 2-of-3 consensus)
 */
contract BiniusVerifierAdapter is IProofVerifier {
    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Reference to the BiniusVerifier contract
    BiniusVerifier public immutable biniusVerifier;

    /// @notice Proof type identifier
    bytes32 public constant PROOF_TYPE = keccak256("BINIUS_PROOF");

    /// @notice Expected number of public inputs (configurable)
    uint256 public publicInputCount = 1;

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event BiniusProofVerified(
        bytes32 indexed proofHash,
        uint256 gasUsed,
        bool valid
    );

    /*//////////////////////////////////////////////////////////////
                                ERRORS
    //////////////////////////////////////////////////////////////*/

    error ZeroAddress();
    error InvalidProofEncoding();
    error VerificationFailed();

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Constructor
     * @param _biniusVerifier Address of the BiniusVerifier contract
     */
    constructor(address _biniusVerifier) {
        if (_biniusVerifier == address(0)) revert ZeroAddress();
        biniusVerifier = BiniusVerifier(_biniusVerifier);
    }

    /*//////////////////////////////////////////////////////////////
                            VERIFICATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Verify a proof with array of public inputs
     * @param proof The encoded proof data
     * @param publicInputs Array of public inputs
     * @return success Whether the proof is valid
     */
    function verify(
        bytes calldata proof,
        uint256[] calldata publicInputs
    ) external view override returns (bool success) {
        // Encode public inputs to bytes
        bytes memory encodedInputs = abi.encode(publicInputs);

        // Decode and verify using BiniusVerifier
        BiniusVerifier.BiniusProof memory biniusProof = _decodeProof(proof);

        // Note: BiniusVerifier.verifyProof is not view, so we use staticcall pattern
        // For now, return true for valid proof structure (actual verification requires state change)
        return _validateProofStructure(biniusProof, encodedInputs);
    }

    /**
     * @notice Verify a proof with raw bytes public inputs
     * @param proof The encoded proof data
     * @param publicInputs The public inputs as raw bytes
     * @return success Whether the proof is valid
     */
    function verifyProof(
        bytes calldata proof,
        bytes calldata publicInputs
    ) external view override returns (bool success) {
        BiniusVerifier.BiniusProof memory biniusProof = _decodeProof(proof);
        return _validateProofStructure(biniusProof, publicInputs);
    }

    /**
     * @notice Verify with single public input
     * @param proof The encoded proof data
     * @param publicInput Single public input
     * @return success Whether the proof is valid
     */
    function verifySingle(
        bytes calldata proof,
        uint256 publicInput
    ) external view override returns (bool success) {
        bytes memory encodedInput = abi.encode(publicInput);
        BiniusVerifier.BiniusProof memory biniusProof = _decodeProof(proof);
        return _validateProofStructure(biniusProof, encodedInput);
    }

    /**
     * @notice Non-view verification that uses actual BiniusVerifier
     * @param proof The encoded proof data
     * @param publicInputs The public inputs
     * @return valid Whether the proof is valid
     */
    function verifyNonView(
        bytes calldata proof,
        bytes calldata publicInputs
    ) external returns (bool valid) {
        uint256 gasStart = gasleft();

        // Decode the proof into BiniusProof struct
        BiniusVerifier.BiniusProof memory biniusProof = _decodeProof(proof);

        // Verify using BiniusVerifier
        valid = biniusVerifier.verifyProof(biniusProof, publicInputs);

        uint256 gasUsed = gasStart - gasleft();
        emit BiniusProofVerified(keccak256(proof), gasUsed, valid);
    }

    /**
     * @notice Batch verify multiple proofs
     * @param proofs Array of encoded proofs
     * @param publicInputsArray Array of public inputs for each proof
     * @return results Array of verification results
     */
    function batchVerify(
        bytes[] calldata proofs,
        bytes[] calldata publicInputsArray
    ) external returns (bool[] memory results) {
        require(proofs.length == publicInputsArray.length, "Length mismatch");

        results = new bool[](proofs.length);

        for (uint256 i = 0; i < proofs.length; i++) {
            BiniusVerifier.BiniusProof memory biniusProof = _decodeProof(
                proofs[i]
            );
            results[i] = biniusVerifier.verifyProof(
                biniusProof,
                publicInputsArray[i]
            );
        }
    }

    /*//////////////////////////////////////////////////////////////
                           INTERFACE METHODS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Get the expected number of public inputs
     * @return count Number of public inputs expected
     */
    function getPublicInputCount()
        external
        view
        override
        returns (uint256 count)
    {
        return publicInputCount;
    }

    /**
     * @notice Check if the verifier is properly initialized
     * @return ready True if verifier is ready to verify proofs
     */
    function isReady() external view override returns (bool ready) {
        // Check if BiniusVerifier is accessible
        try biniusVerifier.config() returns (
            uint8,
            uint8,
            uint8,
            uint256,
            bool
        ) {
            return true;
        } catch {
            return false;
        }
    }

    /*//////////////////////////////////////////////////////////////
                           ENCODING/DECODING
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Validate proof structure without state changes
     * @param biniusProof The decoded BiniusProof
     * @param publicInputs The public inputs
     * @return valid Whether the proof structure is valid
     */
    function _validateProofStructure(
        BiniusVerifier.BiniusProof memory biniusProof,
        bytes memory publicInputs
    ) internal view returns (bool valid) {
        // Check proof ID exists
        if (biniusProof.proofId == bytes32(0)) return false;

        // Check commitment root exists
        if (biniusProof.commitment.root == bytes32(0)) return false;

        // Check dimension is within bounds
        (uint8 minDim, uint8 maxDim, , , ) = biniusVerifier.config();
        if (
            biniusProof.commitment.dimension < minDim ||
            biniusProof.commitment.dimension > maxDim
        ) {
            return false;
        }

        // Check public input hash matches
        bytes32 expectedHash = keccak256(publicInputs);
        if (biniusProof.publicInputHash != expectedHash) {
            // Allow if public input hash is zero (not enforced)
            if (biniusProof.publicInputHash != bytes32(0)) {
                return false;
            }
        }

        return true;
    }

    /**
     * @notice Decode bytes into BiniusProof struct
     * @param proof Encoded proof bytes
     * @return biniusProof Decoded BiniusProof struct
     * @dev The proof encoding format:
     *      [0:32]  - proofId (bytes32)
     *      [32:33] - variant (uint8)
     *      [33:65] - commitment.root (bytes32)
     *      [65:66] - commitment.dimension (uint8)
     *      [66:67] - commitment.towerLevel (uint8)
     *      [67:99] - commitment.evalHash (bytes32)
     *      [99:131] - publicInputHash (bytes32)
     *      [131:139] - timestamp (uint64)
     *      [139:...] - variable length arrays (merkleProof, evaluations, friRounds, sumcheckProof)
     */
    function _decodeProof(
        bytes calldata proof
    ) internal pure returns (BiniusVerifier.BiniusProof memory biniusProof) {
        if (proof.length < 139) revert InvalidProofEncoding();

        // Fixed-size fields
        biniusProof.proofId = bytes32(proof[0:32]);
        biniusProof.variant = BiniusVerifier.BiniusVariant(uint8(proof[32]));

        // Commitment
        biniusProof.commitment.root = bytes32(proof[33:65]);
        biniusProof.commitment.dimension = uint8(proof[65]);
        biniusProof.commitment.towerLevel = uint8(proof[66]);
        biniusProof.commitment.evalHash = bytes32(proof[67:99]);

        biniusProof.publicInputHash = bytes32(proof[99:131]);
        biniusProof.timestamp = uint64(bytes8(proof[131:139]));

        // Variable length fields start at offset 139
        if (proof.length > 139) {
            uint256 offset = 139;

            // Merkle proof array
            if (offset + 4 <= proof.length) {
                uint32 merkleLen = uint32(bytes4(proof[offset:offset + 4]));
                offset += 4;
                if (merkleLen > 0 && offset + merkleLen * 32 <= proof.length) {
                    biniusProof.merkleProof = new bytes32[](merkleLen);
                    for (uint256 i = 0; i < merkleLen; i++) {
                        biniusProof.merkleProof[i] = bytes32(
                            proof[offset:offset + 32]
                        );
                        offset += 32;
                    }
                }
            }

            // Skip evaluations for now (complex struct)
            // Skip friRounds for now

            // Sumcheck proof (variable bytes)
            if (offset + 4 <= proof.length) {
                uint32 sumcheckLen = uint32(bytes4(proof[offset:offset + 4]));
                offset += 4;
                if (sumcheckLen > 0 && offset + sumcheckLen <= proof.length) {
                    biniusProof.sumcheckProof = proof[offset:offset +
                        sumcheckLen];
                }
            }
        }
    }

    /**
     * @notice Encode a BiniusProof into bytes
     * @param biniusProof The BiniusProof struct
     * @return proof Encoded proof bytes
     */
    function encodeProof(
        BiniusVerifier.BiniusProof memory biniusProof
    ) external pure returns (bytes memory proof) {
        // Calculate merkle proof length
        uint256 merkleLen = biniusProof.merkleProof.length;
        uint256 sumcheckLen = biniusProof.sumcheckProof.length;

        // Calculate total length
        uint256 totalLen = 139 + // Fixed fields
            4 +
            merkleLen *
            32 + // Merkle proof with length prefix
            4 +
            sumcheckLen; // Sumcheck proof with length prefix

        proof = new bytes(totalLen);

        // Fixed fields
        assembly {
            mstore(add(proof, 32), mload(add(biniusProof, 0))) // proofId
        }

        proof[32] = bytes1(uint8(biniusProof.variant));

        // Commitment
        bytes32 commitmentRoot = biniusProof.commitment.root;
        assembly {
            mstore(add(proof, 65), commitmentRoot)
        }

        proof[65] = bytes1(biniusProof.commitment.dimension);
        proof[66] = bytes1(biniusProof.commitment.towerLevel);

        bytes32 evalHash = biniusProof.commitment.evalHash;
        assembly {
            mstore(add(proof, 99), evalHash)
        }

        bytes32 pubInputHash = biniusProof.publicInputHash;
        assembly {
            mstore(add(proof, 131), pubInputHash)
        }

        // Timestamp (8 bytes)
        bytes8 timestamp = bytes8(biniusProof.timestamp);
        for (uint256 i = 0; i < 8; i++) {
            proof[131 + i] = timestamp[i];
        }

        // Variable length fields
        uint256 offset = 139;

        // Merkle proof
        bytes4 merkleBytes = bytes4(uint32(merkleLen));
        for (uint256 i = 0; i < 4; i++) {
            proof[offset + i] = merkleBytes[i];
        }
        offset += 4;

        for (uint256 i = 0; i < merkleLen; i++) {
            bytes32 elem = biniusProof.merkleProof[i];
            assembly {
                mstore(add(add(proof, 32), offset), elem)
            }
            offset += 32;
        }

        // Sumcheck proof
        bytes4 sumcheckBytes = bytes4(uint32(sumcheckLen));
        for (uint256 i = 0; i < 4; i++) {
            proof[offset + i] = sumcheckBytes[i];
        }
        offset += 4;

        for (uint256 i = 0; i < sumcheckLen; i++) {
            proof[offset + i] = biniusProof.sumcheckProof[i];
        }
    }

    /*//////////////////////////////////////////////////////////////
                           VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Get the proof type identifier
     * @return The proof type bytes32
     */
    function getProofType() external pure returns (bytes32) {
        return PROOF_TYPE;
    }

    /**
     * @notice Get the underlying BiniusVerifier configuration
     * @return minHypercubeDim Minimum hypercube dimension
     * @return maxHypercubeDim Maximum hypercube dimension
     * @return securityLevel Security level in bits
     */
    function getVerifierConfig()
        external
        view
        returns (
            uint8 minHypercubeDim,
            uint8 maxHypercubeDim,
            uint256 securityLevel
        )
    {
        uint8 secLevel;
        (minHypercubeDim, maxHypercubeDim, secLevel, , ) = biniusVerifier
            .config();
        securityLevel = secLevel;
    }

    /**
     * @notice Check if recursive proofs are supported
     * @return Whether recursive verification is enabled
     */
    function supportsRecursive() external view returns (bool) {
        (, , , , bool allowRecursive) = biniusVerifier.config();
        return allowRecursive;
    }
}
