# Soul Protocol Security Audit Report

**Date:** February 4, 2026  
**Auditor:** Internal Security Review  
**Scope:** Core contracts, cross-chain bridges, privacy primitives  
**Status:** ✅ All Critical and High issues resolved

---

## Executive Summary

This report documents the comprehensive security audit performed on the Soul Protocol codebase. The audit identified and fixed **26 vulnerabilities** across 7 core contracts:

| Severity | Found | Fixed | Remaining |
|----------|-------|-------|-----------|
| Critical | 5 | 5 | 0 |
| High | 6 | 6 | 0 |
| Medium | 15 | 15 | 0 |
| **Total** | **26** | **26** | **0** |

---

## Contracts Audited

| Contract | Path | Lines | Risk Level |
|----------|------|-------|------------|
| ZKBoundStateLocks | `contracts/primitives/ZKBoundStateLocks.sol` | ~1,150 | High |
| CrossChainProofHubV3 | `contracts/bridge/CrossChainProofHubV3.sol` | ~1,220 | High |
| UnifiedNullifierManager | `contracts/privacy/UnifiedNullifierManager.sol` | ~850 | High |
| ConfidentialStateContainerV3 | `contracts/core/ConfidentialStateContainerV3.sol` | ~870 | High |
| CrossChainMessageRelay | `contracts/crosschain/CrossChainMessageRelay.sol` | ~860 | Medium |
| DirectL2Messenger | `contracts/crosschain/DirectL2Messenger.sol` | ~1,040 | Medium |
| CrossChainPrivacyHub | `contracts/privacy/CrossChainPrivacyHub.sol` | ~1,350 | Medium |

---

## Critical Vulnerabilities (5)

### C-1: Nullifier Race Condition in `optimisticUnlock()`
**Contract:** ZKBoundStateLocks  
**Severity:** Critical  
**Status:** ✅ Fixed

**Description:**  
The `optimisticUnlock()` function did not mark the nullifier as used when initiating an optimistic unlock. An attacker could call `optimisticUnlock()` with a nullifier, then immediately call `unlock()` with the same nullifier before the dispute window expires, effectively double-spending.

**Fix:**  
```solidity
// Mark nullifier as used immediately to prevent race condition
nullifierUsed[unlockProof.nullifier] = true;
```

**Commit:** `95d4220`

---

### C-2: Incorrect Error for Premature Finalization
**Contract:** ZKBoundStateLocks  
**Severity:** Critical  
**Status:** ✅ Fixed

**Description:**  
When attempting to finalize an optimistic unlock before the dispute window closed, the contract reverted with `ChallengeWindowClosed` which was misleading and incorrect.

**Fix:**  
Added new error `DisputeWindowStillOpen(bytes32 lockId, uint64 finalizeAfter)` for clarity.

**Commit:** `95d4220`

---

### C-3: Missing Access Control on `submitProofInstant()`
**Contract:** CrossChainProofHubV3  
**Severity:** Critical  
**Status:** ✅ Fixed

**Description:**  
The `submitProofInstant()` function lacked proper access control checks. Anyone could submit instant proofs, bypassing the relayer role requirement and stake requirements.

**Fix:**  
```solidity
if (!rolesSeparated) revert RolesNotSeparated();
if (!hasRole(RELAYER_ROLE, msg.sender)) revert InsufficientStake(0, minRelayerStake);
```

**Commit:** `57d663c`

---

### C-4: Missing Access Control on `submitBatch()`
**Contract:** CrossChainProofHubV3  
**Severity:** Critical  
**Status:** ✅ Fixed

**Description:**  
Same issue as C-3 but for batch submissions. This allowed unauthorized batch proof submissions.

**Fix:**  
Added `rolesSeparated` check and `RELAYER_ROLE` validation.

**Commit:** `57d663c`

---

### C-5: Broken Proof Verification in `_verifyDerivationProof()`
**Contract:** UnifiedNullifierManager  
**Severity:** Critical  
**Status:** ✅ Fixed

**Description:**  
The `_verifyDerivationProof()` function accepted ANY non-empty proof when no verifier was configured, effectively disabling proof verification entirely.

**Fix:**  
```solidity
if (address(derivationProofVerifier) == address(0)) {
    revert("Derivation verifier not configured");
}
return derivationProofVerifier.verifyProof(proof, publicInputs);
```

**Commit:** `57d663c`

---

## High Vulnerabilities (6)

### H-1: EIP-712 Signature Doesn't Bind State Data
**Contract:** ConfidentialStateContainerV3  
**Severity:** High  
**Status:** ✅ Fixed

**Description:**  
The `REGISTER_STATE_TYPEHASH` and struct hash computation didn't include `encryptedStateHash` or `metadata`. An attacker could reuse a valid signature with different encrypted state data.

**Fix:**  
Updated typehash to include all state-binding fields:
```solidity
bytes32 public constant REGISTER_STATE_TYPEHASH = keccak256(
    "RegisterState(bytes32 commitment,address owner,uint256 nonce,uint256 deadline,bytes32 encryptedStateHash,bytes32 metadataHash)"
);
```

**Commit:** `57d663c`

---

### H-2: Hash Collision in `deriveSoulBinding()`
**Contract:** UnifiedNullifierManager  
**Severity:** High  
**Status:** ✅ Fixed

**Description:**  
Used `abi.encodePacked()` with variable-length parameters, which can cause hash collisions.

**Fix:**  
Changed to `abi.encode()` which pads each argument to 32 bytes.

**Commit:** `57d663c`

---

### H-3: `recoverLock()` Bypasses Security Checks
**Contract:** ZKBoundStateLocks  
**Severity:** High  
**Status:** ✅ Fixed

**Description:**  
The emergency recovery function didn't check if the lock was already unlocked and didn't register a nullifier, allowing potential replay attacks.

**Fix:**  
- Added `LockAlreadyUnlocked` check
- Added `nonReentrant` modifier
- Generate and register recovery-specific nullifier

**Commit:** `1bbc246`

---

### H-4: Domain Separator Truncates Large Chain IDs
**Contract:** ZKBoundStateLocks  
**Severity:** High  
**Status:** ✅ Fixed

**Description:**  
The `registerDomain()` function used `uint16` for `chainId`, but chains like Arbitrum (42161), Linea (59144), and Scroll (534352) exceed 65,535.

**Fix:**  
Extended `Domain.chainId` and `Domain.appId` to `uint64`. Updated `registerDomain()` to use `generateDomainSeparatorExtended()`.

**Commit:** `1bbc246`

---

### H-5: Double-Counting of `relayerSuccessCount`
**Contract:** CrossChainProofHubV3  
**Severity:** High  
**Status:** ✅ Fixed

**Description:**  
When a relayer won a challenge, `relayerSuccessCount` was incremented in `resolveChallenge()`. Later, `finalizeProof()` would increment it again.

**Fix:**  
Removed the increment from `resolveChallenge()` - `finalizeProof()` solely responsible.

**Commit:** `1bbc246`

---

### H-6: Challenger Rewards Inaccessible
**Contract:** CrossChainProofHubV3  
**Severity:** High  
**Status:** ✅ Fixed

**Description:**  
Challenge winnings were credited to `relayerStakes[challenger]`, but non-relayer challengers couldn't withdraw because `withdrawStake()` checks `minRelayerStake`.

**Fix:**  
- Added `claimableRewards` mapping
- Added `withdrawRewards()` function
- Challenge winnings now go to `claimableRewards`

**Commit:** `1bbc246`

---

## Medium Vulnerabilities (15)

### Events for Critical Configuration Changes

| ID | Contract | Function | Fix |
|----|----------|----------|-----|
| M-1 | CrossChainProofHubV3 | `setVerifierRegistry()` | Added `VerifierRegistryUpdated` event |
| M-2 | CrossChainProofHubV3 | `setChallengePeriod()` | Added `ChallengePeriodUpdated` event + 10min minimum |
| M-3 | CrossChainProofHubV3 | `setMinStakes()` | Added `MinStakesUpdated` event |
| M-4 | CrossChainProofHubV3 | `setRateLimits()` | Added `RateLimitsUpdated` event |
| M-5 | CrossChainMessageRelay | `setGasLimits()` | Added `GasLimitsUpdated` event |
| M-6 | CrossChainMessageRelay | `setMessageExpiry()` | Added `MessageExpiryUpdated` event |

### Input Validation

| ID | Contract | Issue | Fix |
|----|----------|-------|-----|
| M-7 | DirectL2Messenger | Missing zero-check for `soulHub` | Added validation in constructor |
| M-8 | DirectL2Messenger | No upper bound on `requiredConfirmations` | Added max of 20 |
| M-9 | CrossChainPrivacyHub | Missing zero-checks in `initialize()` | Added for all parameters |
| M-10 | CrossChainProofHubV3 | No minimum for `challengePeriod` | Added 10 minute minimum |

### DoS Prevention

| ID | Contract | Issue | Fix |
|----|----------|-------|-----|
| M-11 | ZKBoundStateLocks | `MAX_ACTIVE_LOCKS` not enforced | Added check in `createLock()` |
| M-12 | ConfidentialStateContainerV3 | Unbounded `_ownerCommitments` | Added `getOwnerCommitmentsPaginated()` |
| M-13 | UnifiedNullifierManager | Unbounded `reverseSoulLookup` | Added `getSourceNullifiersPaginated()` |

### Miscellaneous

| ID | Contract | Issue | Fix |
|----|----------|-------|-----|
| M-14 | CrossChainMessageRelay | Silent batch verification failures | Added `MessageFailed` event emission |
| M-15 | ZKBoundStateLocks | Centralization risk | Added `confirmRoleSeparation()` |

---

## Recommendations

### Immediate Actions (Completed)
- [x] All critical and high vulnerabilities fixed
- [x] All medium vulnerabilities fixed
- [x] Code compiles successfully

### Pre-Mainnet Checklist
1. **Run Foundry Tests**: Install Foundry and run full test suite
2. **Call `confirmRoleSeparation()`**: Ensure admin roles are distributed
3. **External Audit**: Consider professional audit (Trail of Bits, OpenZeppelin)
4. **Formal Verification**: Run Certora specs in `certora/` directory

### Ongoing Security
1. **Bug Bounty**: Consider Immunefi program
2. **Monitoring**: Set up alerts for critical events
3. **Upgrades**: Use timelock for admin operations

---

## Commit History

| Commit | Description |
|--------|-------------|
| `95d4220` | Fix nullifier race condition, add ChallengeRejected event |
| `57d663c` | Fix 5 critical and 2 high severity vulnerabilities |
| `1bbc246` | Fix 4 additional high severity vulnerabilities |
| `8b83c58` | Fix 10 medium severity vulnerabilities |
| `7e5a4b0` | Fix 5 additional medium severity vulnerabilities |

---

## Appendix: Testing Notes

The security fixes have been verified to compile successfully with:
- Solidity 0.8.20 (EVM target: paris)
- Solidity 0.8.24 (EVM target: cancun)

Test execution requires Foundry installation. All Solidity test contracts compile without errors.

---

*This report was generated as part of the Soul Protocol internal security audit process.*
