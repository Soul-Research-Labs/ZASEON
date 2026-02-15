# Soul Protocol - Coverage Tracking

> **Last Updated:** February 2026  
> **Coverage Tool:** Forge + Python Stub System

---

## ⚠️ Known Limitation

Forge coverage fails on this project with **"stack too deep"** errors due to:

1. Complex assembly blocks in ZK verifiers
2. Deep call stacks in verification pipelines
3. Foundry coverage instrumentation overhead

**Workaround:** Use `scripts/run_coverage.py` which swaps complex contracts with stubs.

---

## Test Suite Summary

| Category      | Files                        | Tests | Command                                          |
| ------------- | ---------------------------- | ----- | ------------------------------------------------ |
| Foundry Unit  | `test/foundry/*.t.sol`       | 56    | `forge test --match-path 'test/foundry/*'`       |
| Fuzz          | `test/fuzz/*.t.sol`          | 19    | `forge test --match-path 'test/fuzz/*'`          |
| Invariant     | `test/invariant/*.t.sol`     | 5     | `forge test --match-path 'test/invariant/*'`     |
| Attack        | `test/attack/*.t.sol`        | 6     | `forge test --match-path 'test/attack/*'`        |
| Security      | `test/security/*.t.sol`      | 8     | `forge test --match-path 'test/security/*'`      |
| Gas Benchmark | `test/gas-benchmark/*.t.sol` | 2     | `forge test --match-path 'test/gas-benchmark/*'` |
| Integration   | `test/integration/*.t.sol`   | 6     | `forge test --match-path 'test/integration/*'`   |
| Stress        | `test/stress/*.t.sol`        | 3     | `forge test --match-path 'test/stress/*'`        |

---

## Coverage Status

### Core Contracts (Target: 95%)

| Contract                       | Fuzz Runs | Certora | Foundry Tests | Status    |
| ------------------------------ | --------- | ------- | ------------- | --------- |
| `ZKBoundStateLocks`            | 10,000    | ✅      | ✅ 56 tests   | 🟢 Tested |
| `ConfidentialStateContainerV3` | 10,000    | ✅      | ✅            | 🟢 Tested |
| `CrossChainProofHubV3`         | 10,000    | ✅      | ✅            | 🟢 Tested |
| `NullifierRegistryV3`          | 10,000    | ✅      | ✅            | 🟢 Tested |
| `StealthAddressRegistry`       | 10,000    | ✅      | ✅            | 🟢 Tested |

### Security Contracts (Target: 90%)

| Contract               | Fuzz Runs | Attack Tests | Status                |
| ---------------------- | --------- | ------------ | --------------------- |
| `SecurityModule`       | 10,000    | ✅           | 🟢 Tested             |
| `BridgeCircuitBreaker` | 10,000    | ✅           | 🟢 Tested             |
| `FlashLoanGuard`       | 10,000    | ✅           | 🟢 Tested             |
| `BatchAccumulator`     | 10,000    | —            | 🟡 Needs attack tests |

### Bridge Adapters (Target: 85%)

| Contract                 | Integration Tests | Status                    |
| ------------------------ | ----------------- | ------------------------- |
| `ArbitrumBridgeAdapter`  | ✅                | 🟢                        |
| `OptimismBridgeAdapter`  | ✅                | 🟢                        |
| `ScrollBridgeAdapter`    | —                 | 🟡 Needs integration test |
| `LayerZeroBridgeAdapter` | ✅                | 🟢                        |

### SDK (Target: 80%)

| Module           | Test Status | Status         |
| ---------------- | ----------- | -------------- |
| `NoirProver`     | —           | 🔴 Needs tests |
| `SoulClient`     | —           | 🔴 Needs tests |
| `SoulPrivacySDK` | —           | 🔴 Needs tests |

---

## Alternative Verification Methods

Since direct coverage measurement is limited, we rely on complementary methods:

### 1. Fuzz Testing (Foundry)

```bash
# Standard fuzz testing
forge test --match-path 'test/fuzz/*' --fuzz-runs 10000

# Deep fuzz testing
forge test --match-path 'test/fuzz/*' --fuzz-runs 100000 --fuzz-seed 42
```

**Coverage Equivalent:** Each function fuzzed with 10,000+ runs

### 2. Invariant Testing

```bash
# Standard invariant testing
forge test --match-path 'test/invariant/*' --fuzz-runs 256

# Deep invariant testing
forge test --match-path 'test/invariant/*' --fuzz-runs 1000 --fuzz-depth 100
```

**Files:**

- `test/invariant/ZKSlocksInvariant.t.sol`
- `test/invariant/ConfidentialStateInvariant.t.sol`
- `test/invariant/SecurityModuleInvariant.t.sol`
- `test/invariant/PrivacyInvariants.t.sol`

### 3. Formal Verification (Certora)

```bash
# Run all Certora specs
npm run certora:full
```

**Specs:** 54 CVL specifications covering:

- ZK-SLocks properties
- Nullifier uniqueness
- State transition validity
- Access control
- Bridge security
- Ring signature verification
- Stealth address privacy
- Cross-chain proof hub integrity

### 4. Symbolic Execution (Halmos)

```bash
# Run Halmos symbolic tests
halmos --solver-timeout-assertion 300000 --match-test 'check_'
```

### 5. Property-Based Testing (Echidna)

```bash
# Run Echidna
npm run echidna
```

**Properties:** 6 invariant properties in `test/security/EchidnaHarness.sol`

### 6. K Framework (Algebraic Specs)

```bash
kompile specs/kframework/soul-bridge.k --backend haskell
krun specs/kframework/soul-bridge.k
```

**Specs:** 5 specifications covering bridge state machines and proof verification algebra.

### 7. TLA+ Model Checking

```bash
cd specs/tlaplus && java -jar tla2tools.jar MC_SoulBridge.tla
```

**Properties:** 4 safety properties — TVL conservation, double-spend prevention, bridge liveness, state consistency.

### 8. Storage Layout Verification

```bash
forge inspect <Contract> storage-layout > layout.json
```

**Coverage:** 8 contract pairs checked for upgrade-safe storage layout compatibility.

---

## Running Coverage

### With Stubs (Partial Coverage)

```bash
# Run coverage with stub replacement
python scripts/run_coverage.py --report=summary

# Generate LCOV report
python scripts/run_coverage.py --report=lcov

# Restore contracts if interrupted
python scripts/run_coverage.py --restore
```

### Stubbed Contracts

The following contracts are replaced with simplified stubs during coverage:

| Category  | Contracts                                                               |
| --------- | ----------------------------------------------------------------------- |
| Verifiers | `Groth16VerifierBN254`, `SoulUniversalVerifier`, `GasOptimizedVerifier` |
| Core      | `ZKBoundStateLocks`, `ConfidentialStateContainerV3`                     |
| Privacy   | `StealthAddressRegistry`, `CrossChainPrivacyHub`                        |
| Bridges   | `CrossChainProofHubV3`, `DirectL2Messenger`                             |

---

## Improving Coverage

### Priority Actions

1. **Refactor Complex Functions**
   - Split monolithic functions into smaller units
   - Extract verification logic to libraries
   - Reduce local variable count

2. **Create Coverage-Compatible Wrappers**
   - `contracts-coverage/` directory with testable versions
   - Expose internal functions for testing

3. **Implement Dual-Mode Contracts**
   - Coverage mode with simplified verification
   - Production mode with full verification

---

## CI Pipeline

Coverage runs automatically on:

- Pull requests to `main`
- Push to `develop`

Results uploaded to Codecov (when available).

### Total Test Count

> **4,426 tests** across **189 test suites** — 0 failures as of February 2026.

---

## References

- [Foundry Coverage Issue #3357](https://github.com/foundry-rs/foundry/issues/3357)
- [Stack Too Deep Workarounds](https://docs.soliditylang.org/en/latest/types.html#stack-too-deep)
- [Certora Prover Documentation](https://docs.certora.com/)
