# Privacy Interoperability Layer (PIL)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Solidity](https://img.shields.io/badge/Solidity-0.8.20-blue.svg)](https://docs.soliditylang.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.x-blue.svg)](https://www.typescriptlang.org/)

Cross-chain middleware for private state transfer and zero-knowledge proof verification across heterogeneous blockchain networks.

## Features

- **Confidential State Management** - AES-256-GCM encrypted state containers with ZK proof verification
- **Cross-Chain ZK Bridge** - Transfer proofs between different ZK systems (Groth16, PLONK, FRI-based)
- **Relayer Network** - Decentralized proof aggregation with staking and slashing
- **Atomic Swaps** - HTLC-based private cross-chain swaps with stealth commitments
- **Compliance Layer** - Optional KYC/AML with zero-knowledge selective disclosure

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                   Privacy Interoperability Layer                │
├─────────────────────────────────────────────────────────────────┤
│  Layer 4: Execution Sandbox                                     │
│  PILAtomicSwap  |  PILCompliance  |  PILOracle                  │
├─────────────────────────────────────────────────────────────────┤
│  Layer 3: Relayer Network                                       │
│  CrossChainProofHub + Staking + Slashing                        │
├─────────────────────────────────────────────────────────────────┤
│  Layer 2: Proof Translation                                     │
│  Groth16 BLS12381  |  PLONK  |  FRI  |  Native Adapter          │
├─────────────────────────────────────────────────────────────────┤
│  Layer 1: Confidential State                                    │
│  ConfidentialStateContainer + NullifierRegistry                 │
└─────────────────────────────────────────────────────────────────┘
```

| Layer | Description |
|-------|-------------|
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
│   └── infrastructure/ # Oracles, rate limiting, governance
├── sdk/                # TypeScript SDK
├── relayer/            # Relayer node service
├── compliance/         # Compliance provider service
├── test/               # Test suites
└── docs/               # Documentation
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

## SDK Usage

```typescript
import { PILSDK } from '@pil/sdk';

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

- OpenZeppelin security patterns (Ownable, ReentrancyGuard, Pausable)
- AES-256-GCM encryption for state data
- Pedersen commitments with hiding/binding properties
- Nullifier-based double-spend prevention
- Relayer staking with slashing for misbehavior

## Testing

```bash
npm test                    # Run all tests (23 passing)
npm run test:integration    # Integration tests only
REPORT_GAS=true npm test    # With gas reporting
```

## Roadmap

- [x] Core protocol (state container, verifiers, nullifiers)
- [x] Cross-chain infrastructure (proof hub, relayers, swaps)
- [x] Compliance layer (KYC/AML)
- [ ] PLONK and FRI verifiers
- [ ] TEE attestation integration
- [ ] Security audits
- [ ] Mainnet deployment

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/name`)
3. Commit changes (`git commit -m 'Add feature'`)
4. Push to branch (`git push origin feature/name`)
5. Open a Pull Request

## License

MIT License - see [LICENSE](LICENSE) for details.

## Documentation

- [Architecture Guide](docs/architecture.md)
- [Gas Optimization Report](docs/gas-optimization-report.md)
- [API Documentation](docs/README.md)
