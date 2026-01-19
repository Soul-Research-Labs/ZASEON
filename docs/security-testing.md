# Security Testing & Enhanced Fuzzing Guide

This document describes the security testing infrastructure and enhanced fuzzing mechanisms for the Privacy Interoperability Layer.

## Test Categories

### 1. Security Vulnerability Tests

Location: `test/SecurityVulnerabilityTests.test.js`

These tests cover 10 major vulnerability categories:

| Category | Tests |
|----------|-------|
| **Reentrancy Protection** | Prevents re-entry attacks on state registration |
| **Access Control** | Role-based access, privilege escalation prevention |
| **Integer Overflow** | Handles max uint256 values, zero values |
| **Front-Running** | Nullifier binding, commitment protection |
| **DoS Protection** | Gas efficiency, bounded loops |
| **Emergency Recovery** | Multi-sig requirements, unauthorized escalation |
| **Timestamp Security** | No precise timestamp dependencies |
| **Signature Security** | EIP-712 typed data support |
| **Storage Security** | No storage collisions |
| **Critical Invariants** | Nullifier uniqueness, state count, merkle root |

Run security tests:
```bash
npx hardhat test test/SecurityVulnerabilityTests.test.js
```

### 2. Enhanced Fuzzing Tests

Location: `test/EnhancedFuzzing.test.js`

Property-based fuzzing with advanced techniques:

| Technique | Description |
|-----------|-------------|
| **Random Input Fuzzing** | 100 random state registrations, edge case bytes32 values |
| **Mutation-Based Fuzzing** | Bit flips, byte flips, boundary nudging |
| **Sequence Testing** | Random operation sequences with invariant checking |
| **Property-Based Testing** | Nullifier uniqueness, merkle root monotonicity |
| **Differential Testing** | Hash consistency, derivation consistency |
| **Stress Testing** | Rapid succession, concurrent reads |
| **Boundary Testing** | Max batch sizes, empty/minimal inputs |

Run fuzzing tests:
```bash
npx hardhat test test/EnhancedFuzzing.test.js
```

### 3. Solidity Fuzzing Harnesses (Echidna)

Location: `test/fuzzing/`

#### SecurityVulnerabilityTests.sol
- 12 vulnerability attack simulations
- Invariant functions: `echidna_no_reentrancy()`, `echidna_no_overflow()`, etc.

#### AdvancedFuzzingHarness.sol
- Differential testing with shadow state
- Stateful fuzzing (Initial → Populated → Stressed → Degraded → Recovered)
- Guided fuzzing with interesting value generation
- Mutation testing patterns

#### ChaosEngineeringTests.sol
- Network partition simulation
- Byzantine fault tolerance checking
- Resource exhaustion testing
- BFT safety invariant (2/3 + 1 threshold)

## Running Echidna Fuzzing

Install Echidna:
```bash
# macOS
brew install echidna

# Or use Docker
docker pull trailofbits/echidna
```

Run fuzzing:
```bash
# Security vulnerability harness
echidna . --contract SecurityVulnerabilityTests --config test/fuzzing/echidna.config.yaml

# Advanced fuzzing harness
echidna . --contract AdvancedFuzzingHarness --config test/fuzzing/echidna.config.yaml

# Chaos engineering
echidna . --contract ChaosEngineeringTests --config test/fuzzing/echidna.config.yaml

# Core invariant tests
echidna . --contract EchidnaInvariantTests --config test/fuzzing/echidna.config.yaml
```

## Configuration

Edit `test/fuzzing/echidna.config.yaml`:

```yaml
testMode: assertion       # or "property" for pure property testing
testLimit: 200000         # Number of test iterations
seqLen: 200               # Maximum sequence length
shrinkLimit: 15000        # Shrinking iterations for minimization
coverage: true            # Enable coverage tracking
corpusDir: "echidna-corpus"  # Store interesting inputs
```

## Vulnerability Categories Tested

### Smart Contract Vulnerabilities
1. **Reentrancy** - State changes before external calls
2. **Access Control** - Role verification and separation
3. **Integer Overflow** - Arithmetic operations safety
4. **Front-Running** - Transaction ordering attacks
5. **DoS** - Gas limits and unbounded loops

### Cross-Chain Vulnerabilities
6. **Replay Attacks** - Cross-chain message replay
7. **Signature Malleability** - ECDSA signature attacks
8. **Timestamp Manipulation** - Block timestamp abuse

### Storage Vulnerabilities
9. **Storage Collisions** - Mapping key collisions
10. **Uninitialized Storage** - Default value exploitation

### Logic Vulnerabilities
11. **Business Logic Flaws** - State machine violations
12. **Flash Loan Attacks** - Same-block exploitation

## Test Coverage Targets

| Category | Target | Current |
|----------|--------|---------|
| Security Tests | 100% | ✅ 100% |
| Fuzzing Tests | 100% | ✅ 100% |
| Core Contracts | 95%+ | ✅ Covered |
| Edge Cases | 90%+ | ✅ Covered |

## Interpreting Results

### Hardhat Tests
```
360 passing (3s)
9 pending
```
- **passing**: Tests that validate expected behavior
- **pending**: Skipped tests (typically for manual verification)

### Echidna Output
```
echidna_no_reentrancy: PASSED
echidna_access_control_intact: PASSED
```
- **PASSED**: Invariant held for all generated inputs
- **FAILED**: Counterexample found (investigate!)

## Adding New Tests

### JavaScript Test Template
```javascript
describe("New Security Test", function () {
  it("Should prevent specific vulnerability", async function () {
    const { contract, attacker } = await loadFixture(deployFixture);
    
    // Attempt attack
    await expect(
      contract.connect(attacker).vulnerableFunction()
    ).to.be.revertedWithCustomError(contract, "AccessDenied");
  });
});
```

### Echidna Invariant Template
```solidity
function echidna_new_invariant() public view returns (bool) {
    // Return true if invariant holds
    return someCondition && anotherCondition;
}
```

## CI/CD Integration

Add to your CI pipeline:
```yaml
- name: Security Tests
  run: npx hardhat test test/SecurityVulnerabilityTests.test.js

- name: Fuzzing Tests
  run: npx hardhat test test/EnhancedFuzzing.test.js

- name: Full Test Suite
  run: npx hardhat test
```
