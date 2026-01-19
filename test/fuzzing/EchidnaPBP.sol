// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title EchidnaPBP
 * @notice Echidna fuzzing tests for Policy-Bound Proofs patterns
 * @dev Run with: echidna test/fuzzing/EchidnaPBP.sol --contract EchidnaPBP
 *
 * This is a simplified fuzzer that tests PolicyBoundProofs patterns
 * without importing the full contract to avoid "stack too deep" errors.
 */
contract EchidnaPBP {
    // ========== SIMPLIFIED STATE ==========

    mapping(bytes32 => bool) public policyActive;
    mapping(bytes32 => uint64) public policyExpiry;
    mapping(bytes32 => bytes32) public vkToPolicy;
    mapping(bytes32 => bool) public vkBound;

    bytes32[] public policies;
    bytes32[] public verificationKeys;

    uint256 public totalPolicies;
    uint256 public totalVKs;
    uint256 public totalDeactivated;

    // ========== FUZZING FUNCTIONS ==========

    function fuzz_registerPolicy(bytes32 policyHash, uint64 duration) public {
        if (policyActive[policyHash]) return;
        if (duration == 0) return;

        // Cap duration to reasonable range
        duration = uint64(duration % 365 days) + 1 hours;

        policyActive[policyHash] = true;
        policyExpiry[policyHash] = uint64(block.timestamp) + duration;
        policies.push(policyHash);
        totalPolicies++;
    }

    function fuzz_deactivatePolicy(uint256 idx) public {
        if (policies.length == 0) return;

        bytes32 policyHash = policies[idx % policies.length];
        if (!policyActive[policyHash]) return;

        policyActive[policyHash] = false;
        totalDeactivated++;
    }

    function fuzz_bindVK(bytes32 vkHash, uint256 policyIdx) public {
        if (policies.length == 0) return;
        if (vkBound[vkHash]) return;

        bytes32 policyHash = policies[policyIdx % policies.length];
        if (!policyActive[policyHash]) return;

        // Check policy not expired
        if (block.timestamp > policyExpiry[policyHash]) return;

        vkToPolicy[vkHash] = policyHash;
        vkBound[vkHash] = true;
        verificationKeys.push(vkHash);
        totalVKs++;
    }

    function fuzz_unbindVK(uint256 idx) public {
        if (verificationKeys.length == 0) return;

        bytes32 vkHash = verificationKeys[idx % verificationKeys.length];
        if (!vkBound[vkHash]) return;

        bytes32 policyHash = vkToPolicy[vkHash];
        // Can only unbind if policy is deactivated
        if (policyActive[policyHash]) return;

        vkBound[vkHash] = false;
        vkToPolicy[vkHash] = bytes32(0);
    }

    // ========== INVARIANTS ==========

    /**
     * @notice Total policies should equal registered minus removed
     */
    function echidna_policy_accounting() public view returns (bool) {
        return totalPolicies >= totalDeactivated;
    }

    /**
     * @notice Bound VKs must reference existing policies
     */
    function echidna_vk_policy_exists() public view returns (bool) {
        for (uint256 i = 0; i < verificationKeys.length && i < 10; i++) {
            bytes32 vkHash = verificationKeys[i];
            if (vkBound[vkHash]) {
                bytes32 policyHash = vkToPolicy[vkHash];
                if (policyHash == bytes32(0)) return false;
            }
        }
        return true;
    }

    /**
     * @notice Active policies must have future expiry when created
     */
    function echidna_active_not_expired() public view returns (bool) {
        for (uint256 i = 0; i < policies.length && i < 10; i++) {
            bytes32 policyHash = policies[i];
            if (policyActive[policyHash]) {
                // Expiry should be set
                if (policyExpiry[policyHash] == 0) return false;
            }
        }
        return true;
    }

    /**
     * @notice VK count consistency
     */
    function echidna_vk_count() public view returns (bool) {
        return totalVKs == verificationKeys.length;
    }

    /**
     * @notice Policy count consistency
     */
    function echidna_policy_count() public view returns (bool) {
        return totalPolicies == policies.length;
    }
}
