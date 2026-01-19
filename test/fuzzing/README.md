# PIL v2 Extensive Fuzzing Suite

This directory contains comprehensive Echidna fuzzing tests for all major PIL v2 smart contracts.

## Overview

The fuzzing suite tests security properties across the entire PIL v2 protocol:

| Fuzzer | Contract | Properties Tested |
|--------|----------|-------------------|
| `EchidnaPC3.sol` | ProofCarryingContainer | Container creation, consumption, nullifier uniqueness |
| `EchidnaPBP.sol` | PolicyBoundProofs | Policy registration, deactivation, VK binding |
| `EchidnaEASC.sol` | ExecutionAgnosticStateCommitments | Commitment creation, backend attestation |
| `EchidnaCDNA.sol` | CrossDomainNullifierAlgebra | Domain registration, nullifier computation |
| `EchidnaTimelock.sol` | PILTimelock | Governance operations, delay enforcement |
| `EchidnaVerifierRegistry.sol` | VerifierRegistry | Verifier registration, updates, removal |
| `EchidnaOrchestrator.sol` | PILv2Orchestrator | Coordinated transitions, pause controls |
| `EchidnaVerifiers.sol` | Groth16/PLONK/FRI Verifiers | Random proof rejection, verifier stability |
| `EchidnaAtomicSwap.sol` | PILAtomicSwapV2 | HTLC mechanics, secret verification |
| `EchidnaCompliance.sol` | PILComplianceV2 | KYC verification, sanctions, jurisdictions |
| `EchidnaCrossChainHub.sol` | CrossChainProofHubV3 | Cross-chain proofs, challenges, finalization |
| `EchidnaIntegration.sol` | Cross-Domain Integration | Nullifier isolation, computation determinism |

## Prerequisites

### Install Echidna

**macOS:**
```bash
brew install echidna
```

**Linux (using Nix):**
```bash
nix-env -i echidna
```

**Using pip:**
```bash
pip install echidna-test
```

### Install Dependencies

```bash
npm install
```

## Running Fuzzers

### Run All Fuzzers

```bash
./test/fuzzing/run-all-fuzzers.sh
```

### Run Individual Fuzzers

```bash
# From project root
echidna . --contract EchidnaPC3 --config test/fuzzing/echidna.config.yaml
echidna . --contract EchidnaPBP --config test/fuzzing/echidna.config.yaml
echidna . --contract EchidnaEASC --config test/fuzzing/echidna.config.yaml
echidna . --contract EchidnaCDNA --config test/fuzzing/echidna.config.yaml
echidna . --contract EchidnaTimelock --config test/fuzzing/echidna.config.yaml
echidna . --contract EchidnaVerifierRegistry --config test/fuzzing/echidna.config.yaml
echidna . --contract EchidnaOrchestrator --config test/fuzzing/echidna.config.yaml
echidna . --contract EchidnaVerifiers --config test/fuzzing/echidna.config.yaml
echidna . --contract EchidnaAtomicSwap --config test/fuzzing/echidna.config.yaml
echidna . --contract EchidnaCompliance --config test/fuzzing/echidna.config.yaml
echidna . --contract EchidnaCrossChainHub --config test/fuzzing/echidna.config.yaml
echidna . --contract EchidnaIntegration --config test/fuzzing/echidna.config.yaml
```

### Quick Smoke Test

For faster testing during development:

```bash
echidna . --contract EchidnaPC3 --config test/fuzzing/echidna.config.yaml --test-limit 1000
```

## Configuration

The `echidna.config.yaml` file contains fuzzing parameters:

| Parameter | Value | Description |
|-----------|-------|-------------|
| `testLimit` | 100,000 | Maximum number of test cases per property |
| `seqLen` | 150 | Maximum sequence length of function calls |
| `shrinkLimit` | 10,000 | Maximum shrinking iterations |
| `timeout` | 600 | Timeout per contract (seconds) |
| `dictFreq` | 0.50 | Frequency of dictionary-based value generation |

## Security Properties

### Core Invariants Tested

1. **Nullifier Uniqueness**: Nullifiers cannot be double-spent
2. **State Consistency**: Consumed/finalized counts never exceed totals
3. **Access Control**: Role-based operations enforced
4. **Timing Constraints**: Challenge periods, timelocks respected
5. **Cross-Domain Isolation**: Different domains produce different nullifiers
6. **Determinism**: Same inputs always produce same outputs
7. **Proof Rejection**: Random/invalid proofs always fail verification

### Assertion-Based Properties

Each fuzzer includes `echidna_*` functions that return `bool`:

```solidity
/// @notice Consumed containers should never exceed total
function echidna_consumed_lte_total() public view returns (bool) {
    return totalConsumed <= totalCreated;
}
```

### Assertion Checks

The fuzzers also use `assert()` for immediate property violations:

```solidity
// Different domains should produce different nullifiers
if (chainId1 != chainId2) {
    assert(nullifier1 != nullifier2);
}
```

## Output

Results are saved to `fuzzing-results/` with timestamped logs for each contract.

A successful run shows:
```
✓ EchidnaPC3 passed
✓ EchidnaPBP passed
...
╔══════════════════════════════════════════════════════════════╗
║                     FUZZING SUMMARY                          ║
╚══════════════════════════════════════════════════════════════╝
Passed:  12
Failed:  0
Skipped: 0
Total:   12
```

## Troubleshooting

### Contract Not Found

Ensure the contract is compiled:
```bash
npx hardhat compile
```

### Solidity Version Issues

The contracts require Solidity 0.8.20. Ensure your solc version matches.

### Memory Issues

For large fuzzing runs, increase memory:
```bash
echidna . --contract EchidnaPC3 --config test/fuzzing/echidna.config.yaml +RTS -M8G -RTS
```

## Adding New Fuzzers

1. Create a new file `Echidna<ContractName>.sol` in this directory
2. Import the target contract
3. Create state tracking variables
4. Implement `fuzz_*` functions for operations
5. Implement `echidna_*` invariant functions
6. Add to the `CONTRACTS` array in `run-all-fuzzers.sh`

## Coverage

Coverage data is saved to `echidna-corpus/` and can be analyzed with:

```bash
echidna . --contract EchidnaPC3 --config test/fuzzing/echidna.config.yaml --format text
```

## Integration with CI

For CI integration, use reduced limits:

```bash
echidna . --contract EchidnaPC3 --test-limit 10000 --timeout 60
```

## References

- [Echidna Documentation](https://github.com/crytic/echidna)
- [Building Secure Smart Contracts](https://github.com/crytic/building-secure-contracts)
- [Trail of Bits Fuzzing Guidelines](https://blog.trailofbits.com/2020/03/30/an-echidna-for-all-seasons/)
