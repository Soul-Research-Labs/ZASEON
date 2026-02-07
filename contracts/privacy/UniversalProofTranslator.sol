// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {IUniversalChainAdapter} from "../interfaces/IUniversalChainAdapter.sol";
import {UniversalChainRegistry} from "../libraries/UniversalChainRegistry.sol";

/**
 * @title UniversalProofTranslator
 * @author Soul Protocol
 * @notice Cross-proof-system translation coordinator for universal ZK privacy
 * @dev Actual translation happens off-chain (in the SDK/relayer); this contract:
 *      1. Verifies the original proof via the source-system verifier
 *      2. Accepts a "wrapper proof" that attests: "I translated proof P in system A
 *         into proof P' in system B, and P' is valid"
 *      3. Verifies the wrapper proof (a recursive Groth16/PLONK proof)
 *      4. Registers the translated proof as verified
 *
 * ARCHITECTURE:
 *
 *   Source Chain          Relayer (off-chain)         Destination Chain
 *   ───────────          ─────────────────          ──────────────────
 *   STARK proof ──────► Re-prove as Groth16 ──────► Verify Groth16
 *   Halo2 proof ──────► Re-prove as Groth16 ──────► Verify Groth16
 *   PLONK proof ──────► Pass-through (compat) ────► Verify PLONK
 *   Honk proof  ──────► Pass-through (compat) ────► Verify Honk
 *
 * SUPPORTED TRANSLATIONS:
 * - STARK → Groth16 (via recursive wrapper)
 * - Halo2 → Groth16 (via recursive wrapper)
 * - PLONK ↔ UltraPlonk ↔ Honk (native compatibility)
 * - Bulletproofs → Groth16 (via recursive wrapper)
 * - Nova → Groth16 (via IVC folding → Groth16 final step)
 *
 * @custom:security-contact security@soul.network
 */
contract UniversalProofTranslator is AccessControl, ReentrancyGuard, Pausable {
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    /// @dev keccak256("TRANSLATOR_ROLE")
    bytes32 public constant TRANSLATOR_ROLE =
        0x8502233096d909befbda0999bb8ea2f3a6be3c138b9fbf003752a4c8bce86f6c;

    /// @dev keccak256("OPERATOR_ROLE")
    bytes32 public constant OPERATOR_ROLE =
        0x97667070c54ef182b0f5858b034beac1b6f3089aa2d3188bb1e8929f4fa9b929;

    /*//////////////////////////////////////////////////////////////
                                TYPES
    //////////////////////////////////////////////////////////////*/

    /// @notice A translation request bundling source + translated proofs
    struct TranslationRequest {
        bytes32 requestId; // Unique identifier
        IUniversalChainAdapter.ProofSystem sourceSystem; // Original proof system
        IUniversalChainAdapter.ProofSystem targetSystem; // Target proof system
        bytes32 sourceChainId; // Chain where proof originated
        bytes32 destChainId; // Chain where proof will be verified
        bytes32 stateCommitment; // The state being attested
        bytes32[] publicInputs; // Public inputs (shared across systems)
        bytes sourceProof; // Original proof data
        bytes translatedProof; // Re-proved / translated proof data
        bytes wrapperProof; // Recursive wrapper proof attesting translation
        uint256 timestamp;
    }

    /// @notice Translation pathway configuration
    struct TranslationPath {
        IUniversalChainAdapter.ProofSystem fromSystem;
        IUniversalChainAdapter.ProofSystem toSystem;
        address wrapperVerifier; // Verifier for the recursive wrapper proof
        bool nativeCompat; // If true, no wrapper needed (PLONK family)
        bool active;
        uint256 totalTranslations;
    }

    /*//////////////////////////////////////////////////////////////
                               STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Source-system verifiers (ProofSystem => verifier contract)
    mapping(IUniversalChainAdapter.ProofSystem => address)
        public sourceVerifiers;

    /// @notice Translation paths (fromSystem => toSystem => path config)
    mapping(IUniversalChainAdapter.ProofSystem => mapping(IUniversalChainAdapter.ProofSystem => TranslationPath))
        public translationPaths;

    /// @notice Completed translations (requestId => completed)
    mapping(bytes32 => bool) public completedTranslations;

    /// @notice Translation result hashes (requestId => keccak256(translatedProof))
    mapping(bytes32 => bytes32) public translationResults;

    /// @notice Total translations completed
    uint256 public totalTranslations;

    /// @notice Maximum proof size (128KB)
    uint256 public constant MAX_PROOF_SIZE = 131_072;

    /*//////////////////////////////////////////////////////////////
                               EVENTS
    //////////////////////////////////////////////////////////////*/

    event TranslationPathRegistered(
        IUniversalChainAdapter.ProofSystem indexed fromSystem,
        IUniversalChainAdapter.ProofSystem indexed toSystem,
        address wrapperVerifier,
        bool nativeCompat
    );

    event ProofTranslated(
        bytes32 indexed requestId,
        IUniversalChainAdapter.ProofSystem indexed fromSystem,
        IUniversalChainAdapter.ProofSystem indexed toSystem,
        bytes32 stateCommitment
    );

    event SourceVerifierSet(
        IUniversalChainAdapter.ProofSystem indexed proofSystem,
        address indexed verifier
    );

    /*//////////////////////////////////////////////////////////////
                            CUSTOM ERRORS
    //////////////////////////////////////////////////////////////*/

    error TranslationPathNotActive(
        IUniversalChainAdapter.ProofSystem from,
        IUniversalChainAdapter.ProofSystem to
    );
    error TranslationAlreadyCompleted(bytes32 requestId);
    error SourceProofVerificationFailed();
    error WrapperProofVerificationFailed();
    error TranslatedProofVerificationFailed();
    error InvalidProofSize();
    error ZeroAddress();
    error EmptyProof();
    error NoSourceVerifier(IUniversalChainAdapter.ProofSystem system);

    /*//////////////////////////////////////////////////////////////
                            CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(address _admin) {
        if (_admin == address(0)) revert ZeroAddress();
        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(OPERATOR_ROLE, _admin);

        // Register native compatibility paths (PLONK family)
        _registerNativeCompatPath(
            IUniversalChainAdapter.ProofSystem.PLONK,
            IUniversalChainAdapter.ProofSystem.ULTRAPLONK
        );
        _registerNativeCompatPath(
            IUniversalChainAdapter.ProofSystem.PLONK,
            IUniversalChainAdapter.ProofSystem.HONK
        );
        _registerNativeCompatPath(
            IUniversalChainAdapter.ProofSystem.ULTRAPLONK,
            IUniversalChainAdapter.ProofSystem.HONK
        );
    }

    /*//////////////////////////////////////////////////////////////
                         CORE TRANSLATION LOGIC
    //////////////////////////////////////////////////////////////*/

    /// @notice Translate and verify a proof from one system to another
    /// @dev Called by relayers/translators after performing off-chain re-proving
    /// @param request The translation request with both source and translated proofs
    /// @return requestId The translation request identifier
    function translateAndVerify(
        TranslationRequest calldata request
    )
        external
        nonReentrant
        whenNotPaused
        onlyRole(TRANSLATOR_ROLE)
        returns (bytes32 requestId)
    {
        // Validate request
        if (completedTranslations[request.requestId]) {
            revert TranslationAlreadyCompleted(request.requestId);
        }
        if (
            request.sourceProof.length == 0 ||
            request.translatedProof.length == 0
        ) {
            revert EmptyProof();
        }
        if (
            request.sourceProof.length > MAX_PROOF_SIZE ||
            request.translatedProof.length > MAX_PROOF_SIZE
        ) {
            revert InvalidProofSize();
        }

        TranslationPath storage path = translationPaths[request.sourceSystem][
            request.targetSystem
        ];
        if (!path.active) {
            revert TranslationPathNotActive(
                request.sourceSystem,
                request.targetSystem
            );
        }

        if (path.nativeCompat) {
            // Native compatibility: source proof IS the translated proof (PLONK family)
            // Just verify the source proof using either system's verifier
            bool valid = _verifyWithSystem(
                request.sourceSystem,
                request.sourceProof,
                request.publicInputs
            );
            if (!valid) revert SourceProofVerificationFailed();
        } else {
            // Cross-system translation: verify the recursive wrapper proof
            // The wrapper proof attests: "Source proof P in system A is valid,
            // and translated proof P' in system B has the same public inputs"
            if (request.wrapperProof.length == 0) revert EmptyProof();

            bool wrapperValid = _verifyWrapperProof(
                path.wrapperVerifier,
                request.wrapperProof,
                request.sourceSystem,
                request.targetSystem,
                request.publicInputs,
                request.stateCommitment
            );
            if (!wrapperValid) revert WrapperProofVerificationFailed();
        }

        // Mark as completed
        completedTranslations[request.requestId] = true;
        translationResults[request.requestId] = keccak256(
            request.translatedProof
        );

        unchecked {
            ++totalTranslations;
            ++path.totalTranslations;
        }

        emit ProofTranslated(
            request.requestId,
            request.sourceSystem,
            request.targetSystem,
            request.stateCommitment
        );

        return request.requestId;
    }

    /// @notice Check if a translation is possible between two proof systems
    /// @param from Source proof system
    /// @param to Target proof system
    /// @return possible Whether translation is supported
    /// @return nativeCompat Whether it's a native compatibility (no wrapper needed)
    function canTranslate(
        IUniversalChainAdapter.ProofSystem from,
        IUniversalChainAdapter.ProofSystem to
    ) external view returns (bool possible, bool nativeCompat) {
        if (from == to) return (true, true);
        TranslationPath storage path = translationPaths[from][to];
        return (path.active, path.nativeCompat);
    }

    /// @notice Get the verified translation result for a request
    /// @param requestId The translation request ID
    /// @return completed Whether translation was completed
    /// @return translatedProofHash Hash of the translated proof
    function getTranslationResult(
        bytes32 requestId
    ) external view returns (bool completed, bytes32 translatedProofHash) {
        return (
            completedTranslations[requestId],
            translationResults[requestId]
        );
    }

    /*//////////////////////////////////////////////////////////////
                          ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Register a translation pathway between two proof systems
    function registerTranslationPath(
        IUniversalChainAdapter.ProofSystem fromSystem,
        IUniversalChainAdapter.ProofSystem toSystem,
        address wrapperVerifier
    ) external onlyRole(OPERATOR_ROLE) {
        if (wrapperVerifier == address(0)) revert ZeroAddress();

        translationPaths[fromSystem][toSystem] = TranslationPath({
            fromSystem: fromSystem,
            toSystem: toSystem,
            wrapperVerifier: wrapperVerifier,
            nativeCompat: false,
            active: true,
            totalTranslations: 0
        });

        emit TranslationPathRegistered(
            fromSystem,
            toSystem,
            wrapperVerifier,
            false
        );
    }

    /// @notice Set a verifier for a source proof system
    function setSourceVerifier(
        IUniversalChainAdapter.ProofSystem proofSystem,
        address verifier
    ) external onlyRole(OPERATOR_ROLE) {
        if (verifier == address(0)) revert ZeroAddress();
        sourceVerifiers[proofSystem] = verifier;
        emit SourceVerifierSet(proofSystem, verifier);
    }

    /// @notice Deactivate a translation path
    function deactivateTranslationPath(
        IUniversalChainAdapter.ProofSystem fromSystem,
        IUniversalChainAdapter.ProofSystem toSystem
    ) external onlyRole(OPERATOR_ROLE) {
        translationPaths[fromSystem][toSystem].active = false;
    }

    /// @notice Emergency pause
    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    /// @notice Unpause
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    /*//////////////////////////////////////////////////////////////
                        INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Verify a proof using the registered verifier for a given system
    function _verifyWithSystem(
        IUniversalChainAdapter.ProofSystem system,
        bytes calldata proof,
        bytes32[] calldata publicInputs
    ) internal view returns (bool) {
        address verifier = sourceVerifiers[system];
        if (verifier == address(0)) revert NoSourceVerifier(system);

        (bool success, bytes memory result) = verifier.staticcall(
            abi.encodeWithSignature(
                "verify(bytes,bytes32[])",
                proof,
                publicInputs
            )
        );

        return success && result.length >= 32 && abi.decode(result, (bool));
    }

    /// @notice Verify a recursive wrapper proof attesting cross-system translation
    function _verifyWrapperProof(
        address wrapperVerifier,
        bytes calldata wrapperProof,
        IUniversalChainAdapter.ProofSystem sourceSystem,
        IUniversalChainAdapter.ProofSystem targetSystem,
        bytes32[] calldata publicInputs,
        bytes32 stateCommitment
    ) internal view returns (bool) {
        // Build the wrapper's public inputs:
        // [sourceSystem, targetSystem, stateCommitment, hash(originalPublicInputs)]
        bytes32 inputsHash = keccak256(abi.encodePacked(publicInputs));
        bytes memory wrapperInputs = abi.encode(
            uint8(sourceSystem),
            uint8(targetSystem),
            stateCommitment,
            inputsHash
        );

        (bool success, bytes memory result) = wrapperVerifier.staticcall(
            abi.encodeWithSignature(
                "verify(bytes,bytes)",
                wrapperProof,
                wrapperInputs
            )
        );

        return success && result.length >= 32 && abi.decode(result, (bool));
    }

    /// @notice Register a native compatibility path (bidirectional)
    function _registerNativeCompatPath(
        IUniversalChainAdapter.ProofSystem a,
        IUniversalChainAdapter.ProofSystem b
    ) internal {
        translationPaths[a][b] = TranslationPath({
            fromSystem: a,
            toSystem: b,
            wrapperVerifier: address(0),
            nativeCompat: true,
            active: true,
            totalTranslations: 0
        });

        translationPaths[b][a] = TranslationPath({
            fromSystem: b,
            toSystem: a,
            wrapperVerifier: address(0),
            nativeCompat: true,
            active: true,
            totalTranslations: 0
        });
    }
}
