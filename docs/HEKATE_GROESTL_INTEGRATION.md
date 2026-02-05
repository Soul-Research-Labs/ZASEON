# Hekate-Groestl Integration Guide

## Overview

Hekate-Groestl is a ZK-optimized hash function designed for efficient proof generation over binary tower fields (GF(2^128)). This integration brings hardware-accelerated hashing to Soul Protocol's ZK infrastructure.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    Hekate-Groestl Integration Stack                         │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                     Application Layer                                │   │
│  │  ┌───────────────┐  ┌───────────────┐  ┌───────────────────────┐   │   │
│  │  │ Private Swaps │  │ Merkle Proofs │  │ Cross-Chain Commits   │   │   │
│  │  └───────────────┘  └───────────────┘  └───────────────────────┘   │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                    │                                        │
│  ┌─────────────────────────────────▼───────────────────────────────────┐   │
│  │                     Noir Circuit Layer                               │   │
│  │  ┌─────────────────────────────────────────────────────────────┐   │   │
│  │  │                   noir/hekate_hash                           │   │   │
│  │  │  • HekateGroestlState struct                                 │   │   │
│  │  │  • Algebraic S-Box (x^254 + 0x63)                            │   │   │
│  │  │  • MDS Matrix [1, 1, 2, 3]                                   │   │   │
│  │  │  • 12-round permutation                                      │   │   │
│  │  │  • Merkle tree utilities                                     │   │   │
│  │  └─────────────────────────────────────────────────────────────┘   │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                    │                                        │
│  ┌─────────────────────────────────▼───────────────────────────────────┐   │
│  │                   On-Chain Verification Layer                        │   │
│  │  ┌─────────────────────────────────────────────────────────────┐   │   │
│  │  │           contracts/verifiers/HekateGroestlVerifier.sol      │   │   │
│  │  │  • ZK proof verification                                     │   │   │
│  │  │  • Merkle proof verification                                 │   │   │
│  │  │  • Noir verifier integration                                 │   │   │
│  │  └─────────────────────────────────────────────────────────────┘   │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Performance Characteristics

### Hash Function Comparison

| Hash Function    | ZK Constraints | EVM Gas  | Hardware Accel    | Use Case           |
|------------------|----------------|----------|-------------------|--------------------|
| Hekate-Groestl   | ~500 R1CS      | ~3,000   | PMULL/PCLMULQDQ   | GKR recursion      |
| Poseidon-2       | ~300 R1CS      | ~8,000   | None              | Prime field ZK     |
| Keccak-256       | ~150,000 R1CS  | ~36      | Native EVM        | On-chain commits   |
| SHA-256          | ~30,000 R1CS   | ~60      | Precompile        | Bitcoin compat     |

### Off-Chain Proving Performance

```
Merkle Tree Throughput (depth 20, 1M leaves):
┌────────────────────────────────────────────────┐
│ Hekate-Groestl (HW accelerated): 187,000 H/s  │ ████████████████████
│ Poseidon (no HW accel):          ~50,000 H/s  │ █████
│ SHA-256 (software):              ~100,000 H/s │ ██████████
│ Keccak-256 (software):           ~80,000 H/s  │ ████████
└────────────────────────────────────────────────┘
```

## Technical Details

### Hekate-Groestl Parameters

| Parameter          | Value                    | Description                              |
|--------------------|--------------------------|------------------------------------------|
| Field              | GF(2^128)                | Binary tower field                       |
| State Size         | 4×4 matrix (2048 bits)   | 16 × 128-bit elements                    |
| S-Box              | x^254 + 0x63             | Algebraic, ZK-friendly                   |
| MDS Matrix         | [1, 1, 2, 3]             | Minimal constraint depth                 |
| Rounds             | 12                       | Security margin                          |
| Output             | 256 bits                 | 2 × GF(2^128) elements                   |
| Modulus            | x^128 + x^7 + x^2 + x + 1| GF(2^128) irreducible polynomial        |

### Why Hekate-Groestl?

1. **GKR Recursion Optimization**: Designed specifically for GKR-based proof systems over binary tower fields

2. **Hardware Acceleration**: Leverages PMULL (ARM NEON) and PCLMULQDQ (x86-64) for 3-4x speedup

3. **Algebraic S-Box**: The power map x^254 has efficient ZK circuit representation

4. **Minimal MDS Depth**: [1,1,2,3] coefficients reduce multiplicative depth

## Usage

### Noir Circuit Integration

```noir
use dep::hekate_hash::{hash, hash_pair, merkle_root, verify_merkle_proof};

fn main(secret: Field, expected_commitment: Field) {
    // Single element hash
    let commitment = hash([secret]);
    assert(commitment == expected_commitment);
}

fn verify_membership(
    leaf: Field,
    path: [Field; 20],
    indices: [bool; 20],
    root: Field
) {
    assert(verify_merkle_proof(leaf, path, indices, root));
}
```

### Solidity Verification

```solidity
import "./verifiers/HekateGroestlVerifier.sol";

contract MyContract {
    HekateGroestlVerifier public verifier;
    
    function verifyStateTransition(
        bytes calldata proof,
        bytes32 oldStateRoot,
        bytes32 newStateRoot
    ) external returns (bool) {
        bytes memory publicInputs = abi.encodePacked(
            oldStateRoot,
            newStateRoot
        );
        return verifier.verifyProof(proof, publicInputs);
    }
}
```

## Benchmarking

### Run Solidity Benchmarks

```bash
# Full benchmark suite
forge test --match-contract HekateGroestlBenchmark -vv

# Gas comparison
forge test --match-test benchmark_comparative_summary -vv
```

### Run Noir Benchmarks

```bash
cd noir/hekate_benchmark

# Compile and check constraint count
nargo compile
nargo info

# Run tests
nargo test
```

### Expected Output

```
=== HASH FUNCTION COMPARISON SUMMARY ===

ON-CHAIN GAS COSTS (per 2-to-1 hash):
  Keccak-256:      ~36 gas   (native EVM opcode)
  SHA-256:         ~60 gas   (precompile)
  Poseidon:        ~8000 gas (Solidity implementation)
  Hekate-Groestl:  ~3000 gas (commitment + verify)

ZK CIRCUIT CONSTRAINTS (R1CS/PLONK gates):
  Keccak-256:      ~150,000 constraints
  SHA-256:         ~30,000 constraints
  Poseidon-2:      ~300 constraints
  Hekate-Groestl:  ~500 constraints (GKR-optimized)

OFF-CHAIN PROVING (Merkle tree throughput):
  Poseidon:        ~50,000 hashes/sec (no HW accel)
  Hekate-Groestl:  ~187,000 hashes/sec (with HW accel)
```

## Security Considerations

### ⚠️ Important Notices

1. **Non-NIST Standard**: Hekate-Groestl is a domain-specific hash function, not a NIST-standardized algorithm

2. **Binary Field Operations**: Security relies on the hardness of polynomial equations over GF(2^128)

3. **Hardware Requirements**: Full performance requires PMULL/PCLMULQDQ support

4. **Audit Status**: Review cryptographic parameters before production use

### Recommended Use Cases

| ✅ Good For                        | ❌ Not Recommended For           |
|------------------------------------|----------------------------------|
| GKR recursive proofs               | General-purpose hashing          |
| Binius-based systems               | Non-ZK applications              |
| High-throughput Merkle trees       | Interoperability requirements    |
| Binary field ZK circuits           | Hardware without CLMUL support   |

## File Structure

```
noir/
├── hekate_hash/
│   ├── Nargo.toml           # Package manifest
│   └── src/
│       └── main.nr          # Noir implementation
├── hekate_benchmark/
│   ├── Nargo.toml           # Benchmark package
│   └── src/
│       └── main.nr          # Comparison benchmarks

contracts/verifiers/
├── HekateGroestlVerifier.sol # On-chain verifier
└── VerifierRegistry.sol      # Registry (updated with HEKATE_GROESTL_PROOF)

test/benchmarks/
└── HekateGroestlBenchmark.t.sol # Foundry benchmark suite
```

## Integration Checklist

- [x] Noir circuit implementation (`noir/hekate_hash/`)
- [x] Solidity verifier (`contracts/verifiers/HekateGroestlVerifier.sol`)
- [x] VerifierRegistry integration (HEKATE_GROESTL_PROOF type)
- [x] Benchmark suite (Solidity + Noir)
- [x] Documentation

## References

- [Hekate-Groestl Repository](https://github.com/oumuamua-corp/hekate-groestl)
- [GKR Protocol](https://eprint.iacr.org/2015/1047)
- [Binary Tower Fields](https://eprint.iacr.org/2023/1784)
- [Binius](https://eprint.iacr.org/2023/1126)
