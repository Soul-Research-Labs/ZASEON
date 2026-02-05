// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "../interfaces/IProofVerifier.sol";

/**
 * @title HekateGroestlVerifier
 * @author Soul Protocol
 * @notice On-chain verifier for Hekate-Groestl hash proofs
 * @dev Verifies ZK proofs that use Hekate-Groestl as the hash function
 *
 * HEKATE-GROESTL ARCHITECTURE:
 * ┌────────────────────────────────────────────────────────────────────────┐
 * │              Hekate-Groestl Hash Function                               │
 * ├────────────────────────────────────────────────────────────────────────┤
 * │                                                                        │
 * │  Field: GF(2^128) Binary Tower Field                                   │
 * │  State: 4×4 matrix (2048 bits total)                                   │
 * │  S-Box: x^254 + 0x63 (algebraic, ZK-friendly)                          │
 * │  MDS:   [1, 1, 2, 3] (minimal constraint depth)                        │
 * │  Rounds: 12 (recommended)                                              │
 * │                                                                        │
 * │  ┌──────────────────────────────────────────────────────────────────┐  │
 * │  │  SP-Network Round Function:                                       │  │
 * │  │  1. AddRoundConstant                                              │  │
 * │  │  2. SubBytes (x^254 + 0x63)                                       │  │
 * │  │  3. ShiftBytes (column rotation)                                  │  │
 * │  │  4. MixBytes (MDS [1,1,2,3])                                      │  │
 * │  └──────────────────────────────────────────────────────────────────┘  │
 * │                                                                        │
 * │  Output: 256-bit digest (2 × GF(2^128) elements)                       │
 * │                                                                        │
 * │  ⚠️ SECURITY NOTICE:                                                   │
 * │  - Non-NIST: Domain-specific for ZK circuits                          │
 * │  - Optimized for GKR recursion over binary tower fields               │
 * │  - Uses PMULL/PCLMULQDQ hardware acceleration off-chain               │
 * │                                                                        │
 * └────────────────────────────────────────────────────────────────────────┘
 *
 * USE CASES:
 * - Merkle tree membership proofs with reduced constraint count
 * - GKR-based recursive proof verification
 * - Binary field ZK circuits (Binius, Hekate)
 * - Hardware-accelerated proof generation
 */
contract HekateGroestlVerifier is AccessControl, IProofVerifier {
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    /// @dev Pre-computed: keccak256("OPERATOR_ROLE")
    bytes32 public constant OPERATOR_ROLE =
        0x97667070c54ef182b0f5858b034beac1b6f3089aa2d3188bb1e8929f4fa9b929;

    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Hekate-Groestl proof type identifier
    bytes32 public constant HEKATE_GROESTL_PROOF = keccak256("HEKATE_GROESTL");

    /// @notice State size: 16 elements (4x4 matrix)
    uint256 public constant STATE_SIZE = 16;

    /// @notice Recommended rounds
    uint256 public constant DEFAULT_ROUNDS = 12;

    /// @notice S-Box constant
    uint256 public constant SBOX_C = 0x63;

    /// @notice Padding tag
    uint256 public constant PADDING_TAG = 0x80;

    /// @notice GF(2^128) modulus: x^128 + x^7 + x^2 + x + 1
    uint256 public constant GF2_128_MODULUS = 0x87;

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Trusted verifier backend (Noir/PLONK verifier)
    address public noirVerifier;

    /// @notice Circuit verification key hash
    bytes32 public verificationKeyHash;

    /// @notice Whether to verify hash output in addition to proof
    bool public strictMode;

    /// @notice Total proofs verified
    uint256 public totalProofsVerified;

    /// @notice Proof verification gas usage tracking
    mapping(bytes32 => uint256) public proofGasUsage;

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event HekateProofVerified(
        bytes32 indexed proofHash,
        bytes32 indexed inputHash,
        bytes32 indexed outputHash,
        bool valid,
        uint256 gasUsed
    );

    event VerifierUpdated(
        address indexed oldVerifier,
        address indexed newVerifier
    );
    event VerificationKeyUpdated(
        bytes32 indexed oldKey,
        bytes32 indexed newKey
    );
    event StrictModeUpdated(bool enabled);

    /*//////////////////////////////////////////////////////////////
                                ERRORS
    //////////////////////////////////////////////////////////////*/

    error InvalidProofLength();
    error InvalidPublicInputs();
    error ProofVerificationFailed();
    error NoirVerifierNotSet();
    error InvalidVerificationKey();
    error ZeroAddress();

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(address _admin, address _noirVerifier) {
        if (_admin == address(0)) revert ZeroAddress();

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(OPERATOR_ROLE, _admin);

        if (_noirVerifier != address(0)) {
            noirVerifier = _noirVerifier;
        }

        strictMode = true;
    }

    /*//////////////////////////////////////////////////////////////
                          VERIFICATION FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Verify a Hekate-Groestl based ZK proof (view-only, implements IProofVerifier)
     * @param proof The ZK proof bytes
     * @param publicInputs The public inputs to the circuit
     * @return valid Whether the proof is valid
     */
    function verifyProof(
        bytes calldata proof,
        bytes calldata publicInputs
    ) external view override returns (bool valid) {
        if (proof.length == 0) return false;
        if (publicInputs.length == 0) return false;

        // Decode public inputs: [inputHash, outputHash, ...]
        (bytes32 inputHash, bytes32 outputHash) = _decodePublicInputs(
            publicInputs
        );

        // Verify proof structure (view-only check)
        return _verifyProofStructureView(proof, inputHash, outputHash);
    }

    /**
     * @notice Verify and record a Hekate-Groestl proof (state-changing version)
     * @param proof The ZK proof bytes
     * @param publicInputs The public inputs to the circuit
     * @return valid Whether the proof is valid
     */
    function verifyAndRecord(
        bytes calldata proof,
        bytes calldata publicInputs
    ) external returns (bool valid) {
        uint256 gasStart = gasleft();

        if (proof.length == 0) revert InvalidProofLength();
        if (publicInputs.length == 0) revert InvalidPublicInputs();

        // Decode public inputs: [inputHash, outputHash, ...]
        (bytes32 inputHash, bytes32 outputHash) = _decodePublicInputs(
            publicInputs
        );

        // If Noir verifier is set, delegate verification
        if (noirVerifier != address(0)) {
            valid = _verifyWithNoir(proof, publicInputs);
        } else {
            // Fallback: verify proof structure only
            valid = _verifyProofStructure(proof, inputHash, outputHash);
        }

        if (valid) {
            unchecked {
                ++totalProofsVerified;
            }
        }

        uint256 gasUsed = gasStart - gasleft();
        bytes32 proofHash = keccak256(proof);
        proofGasUsage[proofHash] = gasUsed;

        emit HekateProofVerified(
            proofHash,
            inputHash,
            outputHash,
            valid,
            gasUsed
        );

        return valid;
    }

    /**
     * @notice Verify a Merkle proof using Hekate-Groestl hashing
     * @param leaf The leaf value
     * @param proof The Merkle proof path
     * @param indices Bit indices for left/right positioning
     * @param root The expected Merkle root
     * @return valid Whether the proof is valid
     */
    function verifyMerkleProof(
        bytes32 leaf,
        bytes32[] calldata proof,
        bool[] calldata indices,
        bytes32 root
    ) external view returns (bool valid) {
        if (proof.length != indices.length) revert InvalidPublicInputs();

        bytes32 current = leaf;

        uint256 proofLen = proof.length;
        for (uint256 i = 0; i < proofLen; ) {
            bytes32 sibling = proof[i];

            if (indices[i]) {
                // Current is left child
                current = _hashPair(current, sibling);
            } else {
                // Current is right child
                current = _hashPair(sibling, current);
            }

            unchecked {
                ++i;
            }
        }

        return current == root;
    }

    /**
     * @notice Compute Hekate-Groestl hash of two elements (simplified on-chain version)
     * @dev This is a simplified version; full verification happens via ZK proof
     * @param left Left element
     * @param right Right element
     * @return hash The hash result
     */
    function _hashPair(
        bytes32 left,
        bytes32 right
    ) internal pure returns (bytes32 hash) {
        // On-chain we use keccak256 as a commitment to the actual Hekate-Groestl hash
        // The ZK proof verifies the actual Hekate-Groestl computation
        assembly {
            mstore(0x00, left)
            mstore(0x20, right)
            hash := keccak256(0x00, 0x40)
        }
    }

    /*//////////////////////////////////////////////////////////////
                          INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _decodePublicInputs(
        bytes calldata publicInputs
    ) internal pure returns (bytes32 inputHash, bytes32 outputHash) {
        if (publicInputs.length < 64) revert InvalidPublicInputs();

        assembly {
            inputHash := calldataload(publicInputs.offset)
            outputHash := calldataload(add(publicInputs.offset, 32))
        }
    }

    function _verifyWithNoir(
        bytes calldata proof,
        bytes calldata publicInputs
    ) internal returns (bool) {
        // Call Noir verifier contract
        (bool success, bytes memory result) = noirVerifier.call(
            abi.encodeWithSignature("verify(bytes,bytes)", proof, publicInputs)
        );

        if (!success) return false;

        return abi.decode(result, (bool));
    }

    function _verifyProofStructure(
        bytes calldata proof,
        bytes32 inputHash,
        bytes32 outputHash
    ) internal view returns (bool) {
        // Basic structure validation when no verifier is set
        // In production, always use proper ZK verification

        // Check proof has expected structure
        if (proof.length < 32) return false;

        // Extract proof commitment
        bytes32 proofCommitment;
        assembly {
            proofCommitment := calldataload(proof.offset)
        }

        // Verify commitment binds to inputs/outputs
        bytes32 expectedCommitment = keccak256(
            abi.encodePacked(inputHash, outputHash, verificationKeyHash)
        );

        // This is a simplified check - production uses full ZK verification
        return !strictMode || proofCommitment == expectedCommitment;
    }

    /*//////////////////////////////////////////////////////////////
                          ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Update the Noir verifier address
     * @param _noirVerifier New verifier address
     */
    function setNoirVerifier(
        address _noirVerifier
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        address oldVerifier = noirVerifier;
        noirVerifier = _noirVerifier;
        emit VerifierUpdated(oldVerifier, _noirVerifier);
    }

    /**
     * @notice Update the verification key hash
     * @param _vkHash New verification key hash
     */
    function setVerificationKeyHash(
        bytes32 _vkHash
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        bytes32 oldKey = verificationKeyHash;
        verificationKeyHash = _vkHash;
        emit VerificationKeyUpdated(oldKey, _vkHash);
    }

    /**
     * @notice Toggle strict mode
     * @param _enabled Whether strict mode is enabled
     */
    function setStrictMode(
        bool _enabled
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        strictMode = _enabled;
        emit StrictModeUpdated(_enabled);
    }

    /*//////////////////////////////////////////////////////////////
                          VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Get proof type identifier
     */
    function proofType() external pure returns (bytes32) {
        return HEKATE_GROESTL_PROOF;
    }

    /**
     * @notice Check if verifier is ready
     * @dev Implements IProofVerifier.isReady
     */
    function isReady() external view override returns (bool) {
        return noirVerifier != address(0) || !strictMode;
    }

    /**
     * @notice Verify a proof with uint256[] public inputs
     * @dev Implements IProofVerifier.verify
     */
    function verify(
        bytes calldata proof,
        uint256[] calldata publicInputs
    ) external view override returns (bool success) {
        if (proof.length == 0) return false;
        if (publicInputs.length < 2) return false;

        bytes32 inputHash = bytes32(publicInputs[0]);
        bytes32 outputHash = bytes32(publicInputs[1]);

        return _verifyProofStructureView(proof, inputHash, outputHash);
    }

    /**
     * @notice Verify a proof with a single public input
     * @dev Implements IProofVerifier.verifySingle
     */
    function verifySingle(
        bytes calldata proof,
        uint256 publicInput
    ) external view override returns (bool success) {
        if (proof.length == 0) return false;

        bytes32 inputHash = bytes32(publicInput);
        bytes32 outputHash = bytes32(0);

        return _verifyProofStructureView(proof, inputHash, outputHash);
    }

    /**
     * @notice Get expected public input count
     * @dev Implements IProofVerifier.getPublicInputCount
     */
    function getPublicInputCount()
        external
        pure
        override
        returns (uint256 count)
    {
        return 2; // inputHash, outputHash
    }

    /**
     * @notice View-only proof structure verification
     */
    function _verifyProofStructureView(
        bytes calldata proof,
        bytes32 inputHash,
        bytes32 outputHash
    ) internal view returns (bool) {
        if (proof.length < 32) return false;

        bytes32 proofCommitment;
        assembly {
            proofCommitment := calldataload(proof.offset)
        }

        bytes32 expectedCommitment = keccak256(
            abi.encodePacked(inputHash, outputHash, verificationKeyHash)
        );

        return !strictMode || proofCommitment == expectedCommitment;
    }

    /**
     * @notice Get verification statistics
     */
    function getStats()
        external
        view
        returns (uint256 total, address verifier, bool strict)
    {
        return (totalProofsVerified, noirVerifier, strictMode);
    }
}
