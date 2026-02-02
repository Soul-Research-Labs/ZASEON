# Research Contracts

> ⚠️ **WARNING: These contracts are NOT production-ready.**

This folder contains experimental implementations for research and future development. They are excluded from production builds and audits.

## Contents

| Folder/File | Description | Status |
|-------------|-------------|--------|
| `fhe/` | Fully Homomorphic Encryption (TFHE patterns) | Research - FHE on EVM is impractical |
| `pqc/` | Post-Quantum Cryptography (Dilithium, Kyber, SPHINCS+) | Future - awaiting EVM precompiles |
| `NovaRecursiveVerifier.sol` | Nova IVC implementation | Research - Pasta curves not EVM-native |
| `TriptychSignatures.sol` | Triptych ring signatures | Research - not adopted in production anywhere |
| `TriptychPlusSignatures.sol` | Enhanced Triptych | Research |
| `SeraphisAddressing.sol` | Seraphis 3-key addressing | Research - pending Monero adoption |
| `SeraphisFullProtocol.sol` | Full Seraphis protocol | Research |

## Why These Exist

These implementations serve as:
1. **Reference implementations** for future development
2. **Proof-of-concept** for integration patterns
3. **Research exploration** of cutting-edge cryptography

## When They Might Become Production

| System | Blocker | Estimated Timeline |
|--------|---------|-------------------|
| PQC (Dilithium/Kyber) | EVM precompiles via EIP | 2025-2027 |
| FHE | Hardware acceleration + fhEVM maturity | 2026+ |
| Nova IVC | Pasta curve support or efficient wrapper proofs | Unknown |
| Triptych/Seraphis | Monero mainnet adoption + audit | Unknown |

## Do Not Use

These contracts:
- Have NOT been audited
- May contain bugs or incorrect implementations
- Should NOT secure real value
- Are excluded from mainnet deployments
