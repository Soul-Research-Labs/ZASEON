# Getting Started with PIL

> Quick setup guide. For detailed integration, see [INTEGRATION_GUIDE.md](INTEGRATION_GUIDE.md).

## Prerequisites

- Node.js 18+ | npm 9+ | Git
- RPC endpoint (Sepolia testnet or local Anvil)

---

## Installation

```bash
npm install @pil/sdk
# or from source
git clone https://github.com/pil-network/pil-protocol.git && cd pil-protocol && npm install
```

---

## Quick Start

### 1. Initialize the SDK

```typescript
import { PILSDK } from '@pil/sdk';

// Initialize with your configuration
const pil = new PILSDK({
  rpcUrl: 'https://eth-sepolia.g.alchemy.com/v2/YOUR_KEY',
  privateKey: process.env.PRIVATE_KEY,
  network: 'sepolia'
});

// Connect to PIL contracts
await pil.connect();
```

### 2. Create a ZK-Bound State Lock

```typescript
import { ZKBoundStateLocks } from '@pil/sdk';

// Create a state lock with privacy
const lockResult = await pil.zkSlocks.createLock({
  oldStateCommitment: '0x...',
  transitionPredicateHash: '0x...',
  policyHash: '0x...',
  domainSeparator: await pil.zkSlocks.generateDomainSeparator('ethereum', 1),
  unlockDeadline: Math.floor(Date.now() / 1000) + 3600 // 1 hour
});

console.log('Lock created:', lockResult.lockId);
```

### 3. Bridge Assets Privately

```typescript
import { BridgeFactory } from '@pil/sdk/bridges';

// Create a bridge adapter for Cardano
const bridge = BridgeFactory.create('cardano', {
  evmRpcUrl: 'https://eth-sepolia...',
  cardanoRpcUrl: 'https://cardano-preprod...'
});

// Bridge with privacy
const transfer = await bridge.bridgeWithPrivacy({
  amount: '1000000000000000000', // 1 ETH
  recipient: 'addr_test1...',
  proofParams: {
    nullifier: '0x...',
    commitment: '0x...'
  }
});
```

---

## Core Concepts

**ZK-SLocks:** Atomic state transitions with ZK proofs (Create Lock → Prove → Unlock)  
**Cross-Domain Nullifiers:** Prevent double-spending across all chains  
**Privacy Pools:** Join anonymity sets for enhanced privacy

## Example: Private Transfer

```typescript
import { PILSDK, generateProof } from '@pil/sdk';

const pil = new PILSDK({ rpcUrl: process.env.RPC_URL, privateKey: process.env.PRIVATE_KEY });
await pil.connect();

// Generate commitment/nullifier
const secret = pil.crypto.randomBytes(32);
const nullifier = pil.crypto.poseidon([secret, 0]);
const commitment = pil.crypto.poseidon([secret, 1]);

// Create lock, prove, unlock
const lock = await pil.zkSlocks.createLock({ oldStateCommitment: commitment, /* ... */ });
const proof = await generateProof({ circuit: 'transfer', inputs: { secret, nullifier } });
await pil.zkSlocks.unlock({ lockId: lock.lockId, zkProof: proof.proof, /* ... */ });
```

## Next Steps

[Integration Guide](INTEGRATION_GUIDE.md) • [API Reference](API_REFERENCE.md) • [Architecture](architecture.md)

**Support:** [Discord](https://discord.gg/pil-network) | [GitHub Issues](https://github.com/pil-network/pil-protocol/issues)
