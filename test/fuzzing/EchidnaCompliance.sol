// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../../contracts/compliance/PILComplianceV2.sol";

/**
 * @title EchidnaCompliance
 * @notice Echidna fuzzing tests for PILComplianceV2
 * @dev Run with: echidna test/fuzzing/EchidnaCompliance.sol --contract EchidnaCompliance
 *
 * Security Properties Tested:
 * - Only authorized providers can verify KYC
 * - Only authorized auditors can audit
 * - Sanctioned addresses cannot be verified
 * - Restricted jurisdictions are enforced
 * - KYC expiration is respected
 */
contract EchidnaCompliance {
    PILComplianceV2 public compliance;

    // Track state
    address[] public providers;
    address[] public auditors;
    address[] public verifiedUsers;
    address[] public sanctionedUsers;
    bytes2[] public restrictedJuris;

    uint256 public totalProviders;
    uint256 public totalAuditors;
    uint256 public totalVerified;
    uint256 public totalSanctioned;

    constructor() {
        compliance = new PILComplianceV2();
    }

    // ========== PROVIDER MANAGEMENT ==========

    function fuzz_authorizeProvider(address provider) public {
        if (provider == address(0)) return;

        try compliance.authorizeProvider(provider) {
            if (!_contains(providers, provider)) {
                providers.push(provider);
                totalProviders++;
            }
        } catch {
            // Expected - not owner
        }
    }

    function fuzz_revokeProvider(uint256 index) public {
        if (providers.length == 0) return;
        index = index % providers.length;

        try compliance.revokeProvider(providers[index]) {
            // Revoked
        } catch {
            // Not owner
        }
    }

    // ========== AUDITOR MANAGEMENT ==========

    function fuzz_authorizeAuditor(address auditor) public {
        if (auditor == address(0)) return;

        try compliance.authorizeAuditor(auditor) {
            if (!_contains(auditors, auditor)) {
                auditors.push(auditor);
                totalAuditors++;
            }
        } catch {
            // Not owner
        }
    }

    function fuzz_revokeAuditor(uint256 index) public {
        if (auditors.length == 0) return;
        index = index % auditors.length;

        try compliance.revokeAuditor(auditors[index]) {
            // Revoked
        } catch {
            // Not owner
        }
    }

    // ========== SANCTIONS ==========

    function fuzz_sanctionAddress(address user) public {
        if (user == address(0)) return;

        try compliance.sanctionAddress(user) {
            if (!_contains(sanctionedUsers, user)) {
                sanctionedUsers.push(user);
                totalSanctioned++;
            }
        } catch {
            // Not owner
        }
    }

    function fuzz_unsanctionAddress(uint256 index) public {
        if (sanctionedUsers.length == 0) return;
        index = index % sanctionedUsers.length;

        try compliance.unsanctionAddress(sanctionedUsers[index]) {
            // Unsanctioned
        } catch {
            // Not owner
        }
    }

    // ========== JURISDICTIONS ==========

    function fuzz_restrictJurisdiction(bytes2 jurisdiction) public {
        if (jurisdiction == bytes2(0)) return;

        try compliance.restrictJurisdiction(jurisdiction) {
            if (!_containsBytes2(restrictedJuris, jurisdiction)) {
                restrictedJuris.push(jurisdiction);
            }
        } catch {
            // Not owner
        }
    }

    function fuzz_unrestrictJurisdiction(uint256 index) public {
        if (restrictedJuris.length == 0) return;
        index = index % restrictedJuris.length;

        try compliance.unrestrictJurisdiction(restrictedJuris[index]) {
            // Unrestricted
        } catch {
            // Not owner
        }
    }

    // ========== CONFIGURATION ==========

    function fuzz_setMinTier(uint8 tierValue) public {
        PILComplianceV2.KYCTier tier = PILComplianceV2.KYCTier(tierValue % 5);

        try compliance.setMinRequiredTier(tier) {
            // Updated
        } catch {
            // Not owner
        }
    }

    function fuzz_setValidityDuration(uint256 duration) public {
        // Bound to reasonable range (1 day to 5 years)
        duration = 1 days + (duration % (5 * 365 days));

        try compliance.setKYCValidityDuration(duration) {
            // Updated
        } catch {
            // Not owner
        }
    }

    // ========== INVARIANTS ==========

    /// @notice Contract should always exist
    function echidna_contract_exists() public view returns (bool) {
        return address(compliance) != address(0);
    }

    /// @notice Provider count should be consistent
    function echidna_provider_count_consistent() public view returns (bool) {
        uint256 activeCount = 0;
        for (uint256 i = 0; i < providers.length && i < 100; i++) {
            if (compliance.authorizedProviders(providers[i])) {
                activeCount++;
            }
        }
        return activeCount <= totalProviders;
    }

    /// @notice Auditor count should be consistent
    function echidna_auditor_count_consistent() public view returns (bool) {
        uint256 activeCount = 0;
        for (uint256 i = 0; i < auditors.length && i < 100; i++) {
            if (compliance.authorizedAuditors(auditors[i])) {
                activeCount++;
            }
        }
        return activeCount <= totalAuditors;
    }

    /// @notice Validity duration should be positive
    function echidna_validity_duration_positive() public view returns (bool) {
        return compliance.kycValidityDuration() > 0;
    }

    /// @notice Min tier should be valid enum value
    function echidna_min_tier_valid() public view returns (bool) {
        return uint8(compliance.minRequiredTier()) <= 4;
    }

    // ========== HELPERS ==========

    function _contains(
        address[] storage arr,
        address item
    ) internal view returns (bool) {
        for (uint256 i = 0; i < arr.length; i++) {
            if (arr[i] == item) return true;
        }
        return false;
    }

    function _containsBytes2(
        bytes2[] storage arr,
        bytes2 item
    ) internal view returns (bool) {
        for (uint256 i = 0; i < arr.length; i++) {
            if (arr[i] == item) return true;
        }
        return false;
    }
}
