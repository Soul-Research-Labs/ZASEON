# Privacy Interoperability Layer (PIL)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Solidity](https://img.shields.io/badge/Solidity-0.8.22-blue.svg)](https://docs.soliditylang.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.x-blue.svg)](https://www.typescriptlang.org/)

Cross-chain middleware for private state transfer and zero-knowledge proof verification across heterogeneous blockchain networks.

## Features

- **Confidential State Management** - AES-256-GCM encrypted state containers with ZK proof verification
- **Cross-Chain ZK Bridge** - Transfer proofs between different ZK systems (Groth16, PLONK, FRI-based)
- **Relayer Network** - Decentralized proof aggregation with staking and slashing
- **Atomic Swaps** - HTLC-based private cross-chain swaps with stealth commitments
- **Compliance Layer** - Optional KYC/AML with zero-knowledge selective disclosure
- **ZK-Bound State Locks (ZK-SLocks)** - Novel primitive for cross-chain confidential state transitions with ZK-proof unlocking
- **Advanced Privacy Research** - Triptych O(log n) ring signatures, Nova IVC, Seraphis addressing, FHE integration

### PIL v2 Novel Primitives

- **PC³ (Proof-Carrying Containers)** - Self-authenticating confidential containers with embedded proofs
- **PBP (Policy-Bound Proofs)** - Proofs cryptographically scoped by disclosure policy
- **EASC (Execution-Agnostic State Commitments)** - Backend-independent state verification
- **CDNA (Cross-Domain Nullifier Algebra)** - Domain-separated nullifiers for cross-chain replay protection
- **ZK-SLocks** - Cross-chain confidential state locks with ZK-proof based unlocking and optimistic dispute resolution

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                   Privacy Interoperability Layer                │
├─────────────────────────────────────────────────────────────────┤
│  Layer 7: TEE Attestation                                       │
│  SGX (EPID/DCAP) | TDX | SEV-SNP | TrustZone                    │
├─────────────────────────────────────────────────────────────────┤
│  Layer 6: ZK-Bound State Locks (ZK-SLocks)                      │
│  Cross-chain confidential state transitions | Dispute resolution│
├─────────────────────────────────────────────────────────────────┤
│  Layer 5: PIL v2 Primitives                                     │
│  PC³ | PBP | EASC | CDNA | HH | ADA | CRP                       │
├─────────────────────────────────────────────────────────────────┤
│  Layer 4: Execution Sandbox                                     │
│  PILAtomicSwap  |  PILCompliance  |  PILOracle                  │
├─────────────────────────────────────────────────────────────────┤
│  Layer 3: Relayer Network                                       │
│  CrossChainProofHub + Staking + Slashing                        │
├─────────────────────────────────────────────────────────────────┤
│  Layer 2: Proof Translation                                     │
│  Groth16 (BN254/BLS12-381) | PLONK | FRI/STARK                  │
├─────────────────────────────────────────────────────────────────┤
│  Layer 1: Confidential State                                    │
│  ConfidentialStateContainer + NullifierRegistry                 │
└─────────────────────────────────────────────────────────────────┘
```

| Layer | Description |
|-------|-------------|
| TEE Attestation | Hardware-based attestation for trusted execution environments |
| ZK-SLocks | Cross-chain confidential state locks unlocked via ZK proofs |
| PIL v2 Primitives | Novel cryptographic primitives for advanced privacy operations |
| Confidential State | Encrypted state storage with Pedersen commitments and nullifier tracking |
| Proof Translation | Verifiers for different ZK systems with proof format conversion |
| Relayer Network | Decentralized relayer infrastructure with staking and slashing |
| Execution Sandbox | High-level applications (swaps, compliance, oracles) |

## Project Structure

```
├── contracts/           # Solidity smart contracts
│   ├── core/           # State container, verifiers, nullifier registry
│   ├── bridge/         # Cross-chain proof hub, atomic swaps
│   ├── compliance/     # KYC/AML modules
│   ├── primitives/     # PIL v2 primitives (PC³, PBP, EASC, CDNA)
│   ├── security/       # Time-locked admin, security infrastructure
│   └── infrastructure/ # Oracles, rate limiting, governance
├── circuits/           # Circuit documentation (see noir/)
├── noir/               # Noir ZK circuits 
├── sdk/                # TypeScript SDK
├── specs/              # Formal verification specifications
├── relayer/            # Relayer node service
├── test/               # Test suites
└── docs/               # Documentation
```

## Security Features

### Added Security Stack (January 2026)

PIL includes an advanced added security layer with 6 specialized security modules:

| Module | Purpose | Key Features |
|--------|---------|--------------|
| **RuntimeSecurityMonitor** | Real-time bytecode analysis | Invariant checking, suspicious opcode detection, security scoring |
| **FormalBugBounty** | On-chain bug bounty program | 5-tier severity, encrypted submissions, judge voting, auto-payouts |
| **CryptographicAttestation** | TEE attestation verification | SGX DCAP, TDX, SEV-SNP, ARM CCA, TCB level enforcement |
| **EmergencyResponseAutomation** | Incident management | Runbooks, auto-remediation, incident lifecycle tracking |
| **ZKFraudProof** | Zero-knowledge fraud proofs | Fast finality (1 day vs 7), batch management, prover bonding |
| **ThresholdSignature** | Multi-party signatures | t-of-n ECDSA/BLS/FROST, full DKG protocol |

Plus the **AddedSecurityOrchestrator** that coordinates all modules.

```bash
# Deploy added security stack
npx hardhat run scripts/deploy-added-security.ts --network sepolia
```

See [ADDED_SECURITY_OPERATOR_RUNBOOK.md](docs/ADDED_SECURITY_OPERATOR_RUNBOOK.md) for operational guidance.

### Time-Locked Admin Operations

All sensitive administrative operations go through the `PILTimelock` contract:

- **48-hour minimum delay** for standard operations
- **6-hour emergency delay** for critical operations
- **Multi-confirmation** required before execution
- **7-day grace period** after ready time
- **Predecessor ordering** for dependent operations

```solidity
// Schedule a pause operation
bytes32 opId = timelockAdmin.schedulePausePC3(salt);

// Wait for delay...
// Get confirmations...

// Execute after ready time
timelock.execute(target, 0, data, predecessor, salt);
```

### Formal Verification

The codebase includes formal verification specifications in `specs/`:

- `FormalVerification.spec` - High-level invariants and safety properties
- `PC3.spec` - Certora rules for ProofCarryingContainer
- `Timelock.spec` - Certora rules for PILTimelock

Run with Certora Prover:
```bash
certoraRun specs/PC3.spec --contract ProofCarryingContainer
```

## Quick Start

### Prerequisites

- Node.js >= 18.0.0
- npm >= 9.0.0

### Installation

```bash
git clone https://github.com/soul-research-labs/PIL.git
cd PIL

npm install
npm run compile
```

### Running Tests

```bash
# Run all tests
npm test

# Run with gas reporting
REPORT_GAS=true npm test
```

### Deployment

```bash
# Local network
npx hardhat run scripts/deploy.js --network localhost

# Sepolia testnet
npx hardhat run scripts/deploy.js --network sepolia
```

## Core Contracts

### ConfidentialStateContainer

Manages encrypted confidential states with ZK proof verification.

```solidity
function registerState(
    bytes calldata encryptedState,
    bytes32 commitment,
    bytes32 nullifier,
    bytes calldata proof,
    bytes calldata publicInputs
) external;

function transferState(
    bytes32 oldCommitment,
    bytes calldata newEncryptedState,
    bytes32 newCommitment,
    bytes32 newNullifier,
    bytes calldata proof,
    bytes calldata publicInputs,
    address newOwner
) external;
```

### CrossChainProofHub

Aggregates and relays proofs across chains with gas-optimized batching.

```solidity
function submitProof(
    uint256 destChain,
    bytes calldata proof,
    bytes calldata publicInputs
) external returns (bytes32 messageId);

function registerRelayer() external payable;
function claimBatch(bytes32 batchId) external;
```

### L2 Bridge Adapters

Native bridge adapters for major L2 networks with cross-domain messaging and proof relay.

| Adapter | Chain | Features |
|---------|-------|----------|
| `ArbitrumBridgeAdapter` | Arbitrum One/Nova | Retryable Tickets, Outbox Proofs, Nitro |
| `OptimismBridgeAdapter` | Optimism | CrossDomainMessenger, Bedrock, Fault Proofs |
| `BaseBridgeAdapter` | Base | OP Stack, CCTP for native USDC, Coinbase Attestations |
| `L2ChainAdapter` | All L2s | Generic adapter with zkSync, Scroll, Linea, Polygon zkEVM |

```solidity
// Send proof from L1 to L2
function sendProofToL2(
    bytes32 proofHash,
    bytes calldata proof,
    bytes calldata publicInputs,
    uint256 gasLimit
) external payable returns (bytes32 messageId);

// Receive proof on L2 (called by CrossDomainMessenger)
function receiveProofFromL1(
    bytes32 proofHash,
    bytes calldata proof,
    bytes calldata publicInputs,
    uint256 sourceChainId
) external;
```

### PILAtomicSwap

HTLC-based atomic swaps with stealth address support.

```solidity
function createSwapETH(
    address recipient,
    bytes32 hashLock,
    uint256 timeLock,
    bytes32 commitment
) external payable returns (bytes32 swapId);

function claim(bytes32 swapId, bytes32 secret) external;
```

## PIL v2 Primitives

### ProofCarryingContainer (PC³)

Self-authenticating confidential containers that carry their own correctness and policy proofs.

```solidity
// Create a container with embedded proofs
function createContainer(
    bytes calldata encryptedPayload,
    bytes32 stateCommitment,
    bytes32 nullifier,
    ProofBundle calldata proofs,
    bytes32 policyHash
) external returns (bytes32 containerId);

// Verify container proofs
function verifyContainer(bytes32 containerId) external view returns (VerificationResult memory);

// Consume container (marks nullifier as used)
function consumeContainer(bytes32 containerId) external;

// Export for cross-chain transfer
function exportContainer(bytes32 containerId) external view returns (bytes memory);
```

### PolicyBoundProofs (PBP)

Proofs that are cryptographically scoped by disclosure policy.

```solidity
// Register a disclosure policy
function registerPolicy(DisclosurePolicy calldata policy) external returns (bytes32 policyId);

// Bind verification key to policy
function bindVerificationKey(bytes32 vkHash, bytes32 policyHash) external returns (bytes32 domainSeparator);

// Verify a policy-bound proof
function verifyBoundProof(BoundProof calldata proof, bytes32 vkHash) external returns (VerificationResult memory);
```

### ExecutionAgnosticStateCommitments (EASC)

State commitments that are valid across different execution backends (zkVM, TEE, MPC).

```solidity
// Register an execution backend
function registerBackend(
    BackendType backendType,
    string calldata name,
    bytes32 attestationKey,
    bytes32 configHash
) external returns (bytes32 backendId);

// Create execution-agnostic commitment
function createCommitment(
    bytes32 stateHash,
    bytes32 transitionHash,
    bytes32 nullifier
) external returns (bytes32 commitmentId);

// Attest commitment from a backend
function attestCommitment(
    bytes32 commitmentId,
    bytes32 backendId,
    bytes calldata attestationProof,
    bytes32 executionHash
) external;
```

### CrossDomainNullifierAlgebra (CDNA)

Domain-separated nullifiers that compose across chains, epochs, and applications.

```solidity
// Register a domain for nullifier separation
function registerDomain(
    uint64 chainId,
    bytes32 appId,
    uint64 epochEnd
) external returns (bytes32 domainId);

// Register a nullifier in a domain
function registerNullifier(
    bytes32 domainId,
    bytes32 nullifierValue,
    bytes32 commitmentHash,
    bytes32 transitionId
) external returns (bytes32 nullifier);

// Derive cross-domain nullifier
function registerDerivedNullifier(
    bytes32 parentNullifier,
    bytes32 targetDomainId,
    bytes32 transitionId,
    bytes calldata derivationProof
) external returns (bytes32 childNullifier);

// Consume nullifier (prevent double-spend)
function consumeNullifier(bytes32 nullifier) external;
```

### ZKBoundStateLocks (ZK-SLocks)

Cross-chain confidential state locks that can only be unlocked with valid zero-knowledge proofs.

```solidity
// Create a new ZK-bound state lock
function createLock(
    bytes32 oldStateCommitment,
    bytes32 targetChainCommitment,
    uint64 unlockDeadline,
    bytes32 secretHash,
    bytes32 userEntropy
) external returns (bytes32 lockId);

// Unlock with ZK proof (immediate)
function unlock(UnlockProof calldata proof) external;

// Initiate optimistic unlock (requires bond)
function initiateOptimisticUnlock(
    bytes32 lockId,
    bytes32 newStateCommitment,
    bytes32 nullifier,
    bytes calldata zkProof
) external payable;

// Challenge invalid optimistic unlock
function challengeOptimisticUnlock(
    bytes32 lockId,
    UnlockProof calldata conflictProof
) external;

// Finalize after dispute window
function finalizeOptimisticUnlock(bytes32 lockId) external;

// Register domain for cross-chain coordination
function registerDomain(
    uint16 chainId,
    uint16 appId,
    uint32 epoch,
    string calldata name
) external returns (bytes32 domainSeparator);
```

**Key Features:**
- **Cryptographic State Locking**: Locks bound to state commitments, not addresses
- **ZK-Proof Unlocking**: Only valid zero-knowledge proofs can unlock
- **Optimistic Dispute Resolution**: Economic security with 2-hour challenge window
- **Cross-Domain Nullifiers**: Prevents replay attacks across chains
- **LLVM-Safe**: Explicit bit masking to prevent compiler optimization bugs

### PILv2Orchestrator

Integrates all PIL v2 primitives for coordinated workflows.

```solidity
// Create policy-bound commitment
function createPolicyBoundCommitment(
    bytes32 stateHash,
    bytes32 transitionHash,
    bytes32 nullifier,
    bytes32 policyId
) external returns (bytes32 commitmentId);

// Create coordinated transition across all primitives
function createCoordinatedTransition(
    bytes32 containerId,
    bytes32 containerNullifier,
    bytes32 stateHash,
    bytes32 transitionHash,
    bytes32 domainId,
    bytes32 policyId
) external returns (bytes32 transitionId);
```

## SDK Usage

```typescript
import { PILSDK, PILv2ClientFactory } from '@pil/sdk';

const sdk = new PILSDK({
  rpcUrl: 'https://mainnet.infura.io/v3/YOUR_KEY',
  contracts: {
    stateContainer: '0x...',
    proofHub: '0x...',
    atomicSwap: '0x...'
  }
});

await sdk.initialize();

// Send private state cross-chain
const receipt = await sdk.sendPrivateState({
  targetChain: 137,
  encryptedState: await sdk.encrypt(data, recipientPubKey),
  proof: await sdk.generateProof('state_transfer', inputs)
});

// PIL v2 Primitives Usage
const pilv2 = new PILv2ClientFactory({
  proofCarryingContainer: '0x...',
  policyBoundProofs: '0x...',
  executionAgnosticStateCommitments: '0x...',
  crossDomainNullifierAlgebra: '0x...'
}, provider);

// Create a self-authenticating container
const pc3 = pilv2.proofCarryingContainer();
const { containerId } = await pc3.createContainer({
  encryptedPayload: '0x...',
  stateCommitment: '0x...',
  nullifier: '0x...',
  validityProof: '0x...',
  policyProof: '0x...',
  nullifierProof: '0x...',
  proofExpiry: Math.floor(Date.now() / 1000) + 86400,
  policyHash: '0x...'
});

// Register a disclosure policy
const pbp = pilv2.policyBoundProofs();
const { policyId } = await pbp.registerPolicy({
  name: 'KYC Compliant',
  description: 'Requires identity verification',
  requiresIdentity: true,
  requiresJurisdiction: true,
  requiresAmount: false,
  requiresCounterparty: false,
  minAmount: 0n,
  maxAmount: ethers.MaxUint256,
  allowedAssets: [],
  blockedCountries: [],
  expiresAt: 0
});
```

## Gas Costs

| Function | Average Gas | Notes |
|----------|-------------|-------|
| registerState | ~160,000 | First-time state registration |
| transferState | ~164,000 | State ownership transfer |
| submitProof | ~275,000 | Optimized (67% reduction from v1) |
| createSwapETH | ~248,000 | HTLC swap initiation |
| claim | ~51,000 | Swap claim with secret |

## Security

- OpenZeppelin security patterns (AccessControl, ReentrancyGuard, Pausable)
- AES-256-GCM encryption for state data
- Pedersen commitments with hiding/binding properties
- Nullifier-based double-spend prevention
- Relayer staking with slashing for misbehavior
- LLVM-safe bit operations (explicit masking to prevent compiler optimization bugs)
- EIP-1967 compliant proxy storage slots
- Custom errors for gas-efficient error handling

### Security Tooling

```bash
npm run slither             # Static analysis (Slither)
npm run test:fuzzing        # Property-based fuzzing (14 tests)
npm run certora             # Formal verification (requires API key)
```

See [Security Analysis Report](reports/SECURITY_ANALYSIS_REPORT.md) for detailed findings.

## Advanced Privacy Research (January 2026)

PIL implements cutting-edge privacy research from academic literature:

### Privacy Contracts

| Contract | Paper/Source | Purpose |
|----------|--------------|---------|
| `TriptychSignatures.sol` | Noether & Goodell 2020 | O(log n) ring signatures for large anonymity sets |
| `NovaRecursiveVerifier.sol` | Kothapalli et al. 2022 | Incrementally Verifiable Computation |
| `SeraphisAddressing.sol` | MRL-0015 | 3-key address system with Grootle proofs |
| `FHEPrivacyIntegration.sol` | TFHE/Zama | Fully homomorphic encryption on encrypted data |
| `EncryptedStealthAnnouncements.sol` | MEV-resistant | Encrypted stealth address announcements |
| `PrivacyPreservingRelayerSelection.sol` | VRF-based | Unbiased private relayer selection |
| `ConstantTimeOperations.sol` | Timing attacks | Constant-time cryptographic operations |

### Noir ZK Circuits

```
noir/
├── cross_domain_nullifier/    # Cross-chain nullifier proofs, Merkle membership
├── private_transfer/          # Private transfers with stealth addresses
└── ring_signature/            # CLSAG-style ring signatures
```

### Key Features

- **Triptych**: Ring sizes up to 256 members with O(log n) proof size
- **Nova IVC**: O(1) verification regardless of computation steps
- **Seraphis**: Receive/view/spend key separation with forward secrecy
- **FHE**: 20 encrypted operations (arithmetic, comparison, bitwise)

See [PRIVACY_RESEARCH_IMPLEMENTATION.md](docs/PRIVACY_RESEARCH_IMPLEMENTATION.md) for detailed documentation.

## Post-Quantum Cryptography (PQC)

PIL includes experimental support for post-quantum cryptographic primitives to future-proof the protocol against quantum computing threats.

### Supported Algorithms

| Algorithm | Type | Security Level | Status |
|-----------|------|----------------|--------|
| **Dilithium3** (ML-DSA-65) | Digital Signature | 128-bit quantum | ✅ Implemented |
| **Dilithium5** (ML-DSA-87) | Digital Signature | 192-bit quantum | ✅ Implemented |
| **SPHINCS+-128s** (SLH-DSA) | Digital Signature | 128-bit quantum | ✅ Implemented |
| **SPHINCS+-256s** (SLH-DSA) | Digital Signature | 256-bit quantum | ✅ Implemented |
| **Kyber768** (ML-KEM-768) | Key Encapsulation | 192-bit classical | ✅ Implemented |
| **Kyber1024** (ML-KEM-1024) | Key Encapsulation | 256-bit classical | ✅ Implemented |

### PQC Contracts

```
contracts/pqc/
├── DilithiumVerifier.sol      # NIST ML-DSA signature verification
├── SPHINCSPlusVerifier.sol    # Hash-based signature verification
├── KyberKEM.sol               # ML-KEM key encapsulation
├── PQCRegistry.sol            # Central PQC primitive registry
├── PQCProtectedLock.sol       # ZK-SLocks with PQC protection
└── lib/
    └── HybridSignatureLib.sol # Hybrid ECDSA+PQ signature utilities
```

### Hybrid Signature Scheme

PIL supports hybrid signatures that combine classical ECDSA with post-quantum algorithms for defense-in-depth:

```solidity
// Register PQC for your account
registry.configureAccount(
    PQCPrimitive.Dilithium3,    // Signature algorithm
    PQCPrimitive.Kyber768,       // KEM algorithm
    signatureKeyHash,
    kemKeyHash,
    true                         // Enable hybrid mode
);

// Verify hybrid signature (both must be valid)
bool valid = registry.verifyHybridSignature(
    signer,
    messageHash,
    ecdsaSignature,
    dilithiumSignature,
    dilithiumPublicKey
);
```

### Transition Phases

PIL implements a gradual transition strategy:

1. **ClassicalOnly** - Current phase, only ECDSA required
2. **HybridOptional** - PQC available but optional
3. **HybridMandatory** - Both classical and PQ required
4. **PQPreferred** - PQ preferred, classical still accepted
5. **PQOnly** - Only post-quantum signatures accepted

### SDK Usage

```typescript
import { PQCRegistryClient, PQCAlgorithm } from '@pil/sdk/pqc';

const pqc = new PQCRegistryClient(registryAddress, signer);

// Configure PQC for your account
await pqc.configureAccount(
  PQCAlgorithm.Dilithium3,
  PQCAlgorithm.Kyber768,
  dilithiumPublicKey,
  kyberPublicKey,
  true // enable hybrid
);

// Check if account has PQC enabled
const enabled = await pqc.isPQCEnabled(account);

// Get recommended configuration
const recommended = await pqc.getRecommendedConfig();
```

See [POST_QUANTUM_CRYPTOGRAPHY.md](research/POST_QUANTUM_CRYPTOGRAPHY.md) for detailed research documentation.

## Testing

```bash
npm test                    # Run all tests
npm run test:fuzzing        # Property-based fuzzing tests
npm run test:integration    # Integration tests only
REPORT_GAS=true npm test    # With gas reporting
forge test                  # Run Foundry test suite
```

### Test Suite Status (January 2026)

| Category | Tests | Status |
|----------|-------|--------|
| Attack Simulation | 44 | ✅ Passing |
| Stress Tests | 24 | ✅ Passing |
| PQC Tests | 33 | ✅ Passing |
| Integration Tests | 18 | ✅ Passing |
| Fuzz Tests | 140+ | ✅ Passing |
| Privacy Fuzz Tests | 50+ | ✅ Passing |
| Invariant Tests | 8 | ✅ Passing |
| Symbolic Tests | 30+ | ✅ Working (finds edge cases) |
| L2 Adapter Tests | 23 | ✅ Passing |
| **Total** | **370+** | **All passing** |

### Security Test Categories

```bash
# Attack simulation tests
forge test --match-path "test/attacks/*"

# Stress and gas limit tests
forge test --match-path "test/stress/*"

# Post-quantum cryptography tests
forge test --match-path "test/pqc/*"

# Property-based fuzzing with Echidna
npm run echidna:pqc
```

### PIL v2 Primitives Tests

```bash
# Run PIL v2 primitives tests
npx hardhat test test/PILv2Primitives.test.js
```

Test coverage includes:
- Container creation, verification, and consumption
- Policy registration and binding
- Multi-backend attestation
- Cross-domain nullifier operations
- Batch operations for all primitives
- End-to-end integration tests
- Gas usage benchmarks

## Roadmap

> **See [Full Roadmap](docs/ROADMAP.md) for detailed timeline, milestones, and next steps.**

### ✅ Completed (Q4 2025 - Q1 2026)

- [x] Core protocol (state container, verifiers, nullifiers)
- [x] Cross-chain infrastructure (proof hub, relayers, swaps)
- [x] Compliance layer (KYC/AML)
- [x] PIL v2 primitives (PC³, PBP, EASC, CDNA)
- [x] ZK-Bound State Locks (ZK-SLocks) - Novel cross-chain primitive
- [x] PIL v2 orchestrator integration
- [x] SDK clients for PIL v2 primitives
- [x] PLONK verifier (universal trusted setup support)
- [x] FRI verifier (STARK proof support, transparent setup)
- [x] TEE attestation integration (SGX, TDX, SEV-SNP)
- [x] Homomorphic Hiding (HH) - research grade
- [x] Aggregate Disclosure Algebra (ADA) - research grade
- [x] Composable Revocation Proofs (CRP) - research grade
- [x] Comprehensive test suite (283+ tests passing)
- [x] Security tooling (Slither, Echidna, Certora specs)
- [x] Attack simulation tests (44 tests)
- [x] Stress tests (24 tests)
- [x] LLVM vulnerability hardening
- [x] Local testnet deployment complete
- [x] Cross-chain bridge adapters (10 chains)
  - [x] Ethereum L1/L2 bridges
  - [x] Aztec private L2
  - [x] Bitcoin (SPV + BitVM)
  - [x] StarkNet (Cairo)
  - [x] Solana (Wormhole)
  - [x] LayerZero V2 (120+ chains)
  - [x] Chainlink (CCIP, VRF, Automation)
- [x] **Post-Quantum Cryptography (PQC)**
  - [x] Dilithium signature verification (ML-DSA)
  - [x] SPHINCS+ hash-based signatures (SLH-DSA)
  - [x] Kyber key encapsulation (ML-KEM)
  - [x] Hybrid signature schemes (ECDSA + PQ)
  - [x] PQC-protected ZK-SLocks
  - [x] TypeScript SDK for PQC
- [x] **Advanced Privacy Research (January 2026)**
  - [x] Triptych O(log n) ring signatures (Noether & Goodell 2020)
  - [x] Nova/SuperNova IVC (Kothapalli et al. 2022)
  - [x] Seraphis 3-key addressing (MRL-0015)
  - [x] FHE privacy integration (TFHE/Zama style)
  - [x] Privacy-preserving relayer selection (VRF-based)
  - [x] Encrypted stealth announcements (MEV-resistant)
  - [x] Constant-time operations library
  - [x] Noir ZK circuits (cross-domain nullifier, private transfer, ring signature)

### 🔄 In Progress (Q1 2026)

- [x] Testnet deployment (Sepolia) ✅ Completed Jan 22, 2026
- [x] L2 bridge adapters (Arbitrum, Optimism, Base) ✅ Completed Jan 22, 2026
- [ ] L2 testnet deployments (need testnet ETH)
- [ ] Professional security audit
- [ ] 100% test coverage
- [ ] Developer tutorials & documentation

### ⏳ Upcoming (Q2-Q3 2026)

- [ ] Testnet deployment (multi-chain L2s)
- [ ] SDK v1.0 release
- [ ] Relayer network beta
- [ ] Bug bounty program
- [ ] Mainnet deployment (Q3 2026)

### 🔮 Future (Q4 2026+)

- [ ] ARM TrustZone support
- [x] Recursive SNARK / Nova integration ✅ Completed Jan 23, 2026
- [ ] Private DEX & DeFi applications
- [ ] Decentralized governance
- [ ] Enterprise features
- [ ] 50+ chain support

## Proof System Support

| System | Contract | Status |
|--------|----------|--------|
| Groth16 (BN254) | `Groth16VerifierBN254.sol` | ✅ Production |
| Groth16 (BLS12-381) | `Groth16VerifierBLS12381.sol` | ✅ Production |
| PLONK | `PLONKVerifier.sol` | ✅ Production |
| FRI/STARK | `FRIVerifier.sol` | ✅ Production |

## L2 Interoperability

PIL provides native integration with major Ethereum L2 networks through dedicated bridge adapters.

| Network | Chain ID | Adapter | Features |
|---------|----------|---------|----------|
| Arbitrum One | 42161 | `ArbitrumBridgeAdapter` | Nitro, Retryable Tickets, 7-day challenge |
| Arbitrum Nova | 42170 | `ArbitrumBridgeAdapter` | AnyTrust, lower fees |
| Optimism | 10 | `OptimismBridgeAdapter` | OP Stack, Bedrock, Fault Proofs |
| Base | 8453 | `BaseBridgeAdapter` | OP Stack, CCTP (native USDC), Coinbase attestations |
| zkSync Era | 324 | `L2ChainAdapter` | ZK Rollup, native account abstraction |
| Scroll | 534352 | `L2ChainAdapter` | zkEVM, EVM equivalence |
| Linea | 59144 | `L2ChainAdapter` | zkEVM, Consensys |
| Polygon zkEVM | 1101 | `L2ChainAdapter` | zkEVM, Polygon ecosystem |

### Cross-Chain Proof Flow

```
┌─────────────────┐      ┌─────────────────┐      ┌─────────────────┐
│   L1 Ethereum   │      │  CrossDomain    │      │   L2 Network    │
│                 │      │  Messenger      │      │                 │
│  ┌───────────┐  │      │                 │      │  ┌───────────┐  │
│  │ PIL Core  │──┼──────┼─────────────────┼──────┼─►│ L2 Adapter│  │
│  │ Contracts │  │      │                 │      │  └───────────┘  │
│  └───────────┘  │      │                 │      │        │        │
│       │         │      │                 │      │        ▼        │
│  ┌────▼──────┐  │      │                 │      │  ┌───────────┐  │
│  │ L1 Bridge │──┼──────┼────►[Proof]─────┼──────┼─►│ Proof     │  │
│  │ Adapter   │  │      │                 │      │  │ Relay     │  │
│  └───────────┘  │      │                 │      │  └───────────┘  │
└─────────────────┘      └─────────────────┘      └─────────────────┘
```

### Usage Example

```typescript
import { PILClient, ArbitrumBridgeAdapter } from "@pil/sdk";

// Initialize PIL client
const client = new PILClient({
  l1Provider: l1Provider,
  l2Provider: arbitrumProvider,
});

// Relay proof from Ethereum to Arbitrum
const messageId = await client.bridges.arbitrum.sendProofToL2({
  proofHash: proof.hash,
  proof: proof.data,
  publicInputs: proof.inputs,
  gasLimit: 1_000_000n,
});

// Wait for relay confirmation
await client.bridges.arbitrum.waitForRelay(messageId);
```

## TEE Support

| Platform | Description | Status |
|----------|-------------|--------|
| Intel SGX EPID | Legacy attestation | ✅ Supported |
| Intel SGX DCAP | Modern datacenter attestation | ✅ Supported |
| Intel TDX | Trust Domain Extensions | ✅ Supported |
| AMD SEV-SNP | Secure Encrypted Virtualization | ✅ Supported |
| ARM TrustZone | Mobile TEE | 🔄 Planned |

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/name`)
3. Commit changes (`git commit -m 'Add feature'`)
4. Push to branch (`git push origin feature/name`)
5. Open a Pull Request

## License

MIT License - see [LICENSE](LICENSE) for details.

## Deployments

### Local Testnet (Hardhat)

Deployed to localhost (Chain ID: 31337):

| Contract | Address |
|----------|--------|
| VerifierRegistry | `0x67d269191c92Caf3cD7723F116c85e6E9bf55933` |
| Groth16VerifierBN254 | `0xE6E340D132b5f46d1e472DebcD681B2aBc16e57E` |
| PLONKVerifier | `0xc3e53F4d16Ae77Db1c982e75a937B9f60FE63690` |
| FRIVerifier | `0x84eA74d481Ee0A5332c457a4d796187F6Ba67fEB` |
| TEEAttestation | `0x9E545E3C0baAB3E08CdfD552C960A1050f373042` |
| ProofCarryingContainer | `0xa82fF9aFd8f496c3d6ac40E2a0F282E47488CFc9` |
| PolicyBoundProofs | `0x1613beB3B2C4f22Ee086B2b38C1476A3cE7f78E8` |
| ExecutionAgnosticStateCommitments | `0x851356ae760d987E095750cCeb3bC6014560891C` |
| CrossDomainNullifierAlgebra | `0xf5059a5D33d5853360D16C683c16e67980206f36` |
| PILv2Orchestrator | `0x95401dc811bb5740090279Ba06cfA8fcF6113778` |
| PILTimelock | `0x998abeb3E57409262aE5b751f60747921B33613E` |
| TimelockAdmin | `0x70e0bA845a1A0F2DA3359C97E0285013525FFC49` |

### Sepolia Testnet ✅ DEPLOYED

**Deployment Date**: January 22, 2026  
**Deployer**: `0xbc5bb932c7696412622b1fe9a09b7fd9509c6913`  
**Chain ID**: 11155111

| Contract | Address |
|----------|---------|
| MockProofVerifier | [`0x1f830a178020d9d9b968b9f4d13e6e4cdbc9fa57`](https://sepolia.etherscan.io/address/0x1f830a178020d9d9b968b9f4d13e6e4cdbc9fa57) |
| Groth16VerifierBLS12381 | [`0x09cf3f57c213218446aa49d89236247fbe1d08bd`](https://sepolia.etherscan.io/address/0x09cf3f57c213218446aa49d89236247fbe1d08bd) |
| PLONKVerifier | [`0x7c73fbd4affdd797c7dae7a1fb23bfd6ced387f2`](https://sepolia.etherscan.io/address/0x7c73fbd4affdd797c7dae7a1fb23bfd6ced387f2) |
| FRIVerifier | [`0x2e9fceb9a74fba5d8edb6420b350a4edd242bb09`](https://sepolia.etherscan.io/address/0x2e9fceb9a74fba5d8edb6420b350a4edd242bb09) |
| ConfidentialStateContainerV3 | [`0x5d79991daabf7cd198860a55f3a1f16548687798`](https://sepolia.etherscan.io/address/0x5d79991daabf7cd198860a55f3a1f16548687798) |
| NullifierRegistryV3 | [`0x3e21d559f19c76a0bcec378b10dae2cc0e4c2191`](https://sepolia.etherscan.io/address/0x3e21d559f19c76a0bcec378b10dae2cc0e4c2191) |
| CrossChainProofHubV3 | [`0x40eaa5de0c6497c8943c967b42799cb092c26adc`](https://sepolia.etherscan.io/address/0x40eaa5de0c6497c8943c967b42799cb092c26adc) |
| PILAtomicSwapV2 | [`0xdefb9a66dc14a6d247b282555b69da7745b0ab57`](https://sepolia.etherscan.io/address/0xdefb9a66dc14a6d247b282555b69da7745b0ab57) |
| PILComplianceV2 | [`0x5d41f63f35babed689a63f7e5c9e2943e1f72067`](https://sepolia.etherscan.io/address/0x5d41f63f35babed689a63f7e5c9e2943e1f72067) |
| ProofCarryingContainer (PC³) | [`0x52f8a660ff436c450b5190a84bc2c1a86f1032cc`](https://sepolia.etherscan.io/address/0x52f8a660ff436c450b5190a84bc2c1a86f1032cc) |
| PolicyBoundProofs (PBP) | [`0x75e86ee654eae62a93c247e4ab9facf63bc4f328`](https://sepolia.etherscan.io/address/0x75e86ee654eae62a93c247e4ab9facf63bc4f328) |
| ExecutionAgnosticStateCommitments (EASC) | [`0x77d22cb55253fea1ccc14ffc86a22e4a5a4592c6`](https://sepolia.etherscan.io/address/0x77d22cb55253fea1ccc14ffc86a22e4a5a4592c6) |
| CrossDomainNullifierAlgebra (CDNA) | [`0x674d0cbfb5bf33981b1656abf6a47cff46430b0c`](https://sepolia.etherscan.io/address/0x674d0cbfb5bf33981b1656abf6a47cff46430b0c) |
| TEEAttestation | [`0x43fb20b97b4a363c0f98f534a078f7a0dd1dcdbb`](https://sepolia.etherscan.io/address/0x43fb20b97b4a363c0f98f534a078f7a0dd1dcdbb) |
| EmergencyRecovery | [`0x1995dbb199c26afd73a817aaafbccbf28f070ffc`](https://sepolia.etherscan.io/address/0x1995dbb199c26afd73a817aaafbccbf28f070ffc) |
| ZKBoundStateLocks | [`0xf390ae12c9ce8f546ef7c7adaa6a1ab7768a2c78`](https://sepolia.etherscan.io/address/0xf390ae12c9ce8f546ef7c7adaa6a1ab7768a2c78) |
| ZKSLockIntegration | [`0x668c1a8197d59b5cf4d3802e209d3784c6f69b29`](https://sepolia.etherscan.io/address/0x668c1a8197d59b5cf4d3802e209d3784c6f69b29) |

**Total Contracts**: 17

To redeploy to Sepolia:

1. Copy `.env.example` to `.env` and add your private key
2. Get Sepolia ETH from [sepoliafaucet.com](https://sepoliafaucet.com)
3. Run: `npx hardhat run scripts/deploy-v3.ts --network sepolia`

### L2 Testnets (Pending)

| Network | Status | Chain ID |
|---------|--------|----------|
| Arbitrum Sepolia | ⏳ Pending | 421614 |
| Base Sepolia | ⏳ Pending | 84532 |
| Optimism Sepolia | ⏳ Pending | 11155420 |

## Documentation

- [Architecture Guide](docs/architecture.md)
- [Privacy Research Implementation](docs/PRIVACY_RESEARCH_IMPLEMENTATION.md)
- [Cross-Chain Privacy](docs/CROSS_CHAIN_PRIVACY.md)
- [L2 Interoperability](docs/L2_INTEROPERABILITY.md)
- [Security Audit Preparation](docs/SECURITY_AUDIT_PREPARATION.md)
- [Incident Response Runbook](docs/INCIDENT_RESPONSE_RUNBOOK.md)
- [Added Security Operator Runbook](docs/ADDED_SECURITY_OPERATOR_RUNBOOK.md)
- [Gas Optimization Report](docs/gas-optimization-report.md)
- [Deployment Guide](docs/DEPLOYMENT.md)
- [API Documentation](docs/README.md)
