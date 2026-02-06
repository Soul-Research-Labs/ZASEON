// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title PQCPrecompileDetector
 * @author Soul Protocol
 * @notice Runtime detection of PQC precompile availability
 * @dev Returns precompile availability status without reverting.
 *      Used by DilithiumVerifier, SPHINCSPlusVerifier, and KyberKEM to
 *      auto-fallback from Precompile → OffchainZK → PureSolidity mode.
 *
 * ╔═══════════════════════════════════════════════════════════════════════════╗
 * ║                    PQC PRECOMPILE DETECTION                                ║
 * ╠═══════════════════════════════════════════════════════════════════════════╣
 * ║                                                                           ║
 * ║ Proposed EIP precompiles (not yet deployed on any network):              ║
 * ║ • 0x0D — Dilithium / ML-DSA (FIPS 204)                                  ║
 * ║ • 0x0E — SPHINCS+ / SLH-DSA (FIPS 205)                                  ║
 * ║ • 0x0F — Kyber / ML-KEM (FIPS 203)                                      ║
 * ║                                                                           ║
 * ║ Detection method:                                                        ║
 * ║ 1. Check if address has code (EXTCODESIZE > 0)                          ║
 * ║ 2. Send a minimal probe call with low gas                               ║
 * ║ 3. If both succeed, precompile is available                             ║
 * ║                                                                           ║
 * ║ Note: Native precompiles (ecrecover at 0x01, etc.) have code size 0     ║
 * ║ but still respond to staticcall. We use the probe approach.             ║
 * ╚═══════════════════════════════════════════════════════════════════════════╝
 *
 * @custom:security-contact security@soulprotocol.io
 */
library PQCPrecompileDetector {
    /// @notice Proposed precompile addresses
    address internal constant DILITHIUM_PRECOMPILE = address(0x0D);
    address internal constant SPHINCS_PRECOMPILE = address(0x0E);
    address internal constant KYBER_PRECOMPILE = address(0x0F);

    /// @notice Gas limit for probe calls (enough for precompile, not enough for abuse)
    uint256 internal constant PROBE_GAS = 10_000;

    /**
     * @notice Check if a precompile address is responsive
     * @dev Sends a minimal staticcall to detect if the address responds.
     *      Native EVM precompiles (0x01-0x0A) respond to staticcall even with
     *      extcodesize == 0, so we use the same approach for PQC precompiles.
     * @param precompileAddr The precompile address to probe
     * @return available True if the precompile responds to calls
     */
    function isPrecompileAvailable(
        address precompileAddr
    ) internal view returns (bool available) {
        // Send a minimal probe — empty calldata
        // Real precompiles will return (possibly with an error for bad input)
        // Non-existent addresses will return success with empty data (no code)
        (bool success, bytes memory result) = precompileAddr.staticcall{
            gas: PROBE_GAS
        }("");

        // A real precompile will either:
        // 1. Return success with data (valid empty input handled)
        // 2. Return failure with data (invalid input, but precompile exists)
        // A non-existent address returns success with empty data
        // We consider it available if it returns data (either success or failure)
        if (result.length > 0) {
            return true;
        }

        // Also check with a known-format probe (algorithm byte + 32-byte message)
        bytes memory probe = abi.encode(uint8(0), bytes32(0));
        (success, result) = precompileAddr.staticcall{gas: PROBE_GAS}(probe);

        // If we got any response data, the precompile exists
        return result.length > 0;
    }

    /**
     * @notice Check if Dilithium precompile (0x0D) is available
     * @return available True if ML-DSA precompile is responsive
     */
    function isDilithiumAvailable() internal view returns (bool) {
        return isPrecompileAvailable(DILITHIUM_PRECOMPILE);
    }

    /**
     * @notice Check if SPHINCS+ precompile (0x0E) is available
     * @return available True if SLH-DSA precompile is responsive
     */
    function isSPHINCSAvailable() internal view returns (bool) {
        return isPrecompileAvailable(SPHINCS_PRECOMPILE);
    }

    /**
     * @notice Check if Kyber precompile (0x0F) is available
     * @return available True if ML-KEM precompile is responsive
     */
    function isKyberAvailable() internal view returns (bool) {
        return isPrecompileAvailable(KYBER_PRECOMPILE);
    }

    /**
     * @notice Get availability status of all PQC precompiles
     * @return dilithium True if 0x0D is responsive
     * @return sphincs True if 0x0E is responsive
     * @return kyber True if 0x0F is responsive
     */
    function getAllAvailability()
        internal
        view
        returns (bool dilithium, bool sphincs, bool kyber)
    {
        dilithium = isDilithiumAvailable();
        sphincs = isSPHINCSAvailable();
        kyber = isKyberAvailable();
    }
}
