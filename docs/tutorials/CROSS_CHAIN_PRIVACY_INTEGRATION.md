# Cross-Chain Private Transfer Integration Guide

This guide walks you through integrating PIL's cross-chain private transfer capability into your application.

## Overview

PIL enables fully private value transfers across chains while preventing double-spending through cross-domain nullifiers. The flow involves:

1. **Shielding** - Deposit funds into a privacy pool
2. **Proving** - Generate a ZK proof of ownership
3. **Relaying** - Transmit commitment across chains
4. **Claiming** - Withdraw privately on the destination chain

## Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   Source Chain  │     │   Relay Layer   │     │   Dest Chain    │
│   (Ethereum)    │     │   (LayerZero/   │     │   (Optimism)    │
│                 │     │    Hyperlane)   │     │                 │
│  ┌───────────┐  │     │                 │     │  ┌───────────┐  │
│  │ Privacy   │──┼─────┼─────────────────┼─────┼─>│ Privacy   │  │
│  │ Hub       │  │     │  Commitment +   │     │  │ Hub       │  │
│  └───────────┘  │     │  Proof Relay    │     │  └───────────┘  │
│       │         │     │                 │     │       │         │
│  ┌───────────┐  │     │                 │     │  ┌───────────┐  │
│  │ Nullifier │  │     │  Cross-Domain   │     │  │ Nullifier │  │
│  │ Registry  │<─┼─────┼─── Nullifier ───┼─────┼->│ Registry  │  │
│  └───────────┘  │     │     Sync        │     │  └───────────┘  │
└─────────────────┘     └─────────────────┘     └─────────────────┘
```

## Prerequisites

```bash
npm install @pil/sdk ethers
```

## Step 1: Initialize Clients

```typescript
import {
  PrivacyHubClient,
  NullifierClient,
  CrossChainPrivacyOrchestrator,
  ChainConfig
} from '@pil/sdk';
import { ethers } from 'ethers';

// Configure chains
const chainConfigs: Record<number, ChainConfig> = {
  1: {
    chainId: 1,
    name: 'Ethereum',
    privacyHub: '0x...ethPrivacyHub',
    nullifierRegistry: '0x...ethNullifierRegistry',
    rpcUrl: 'https://eth-mainnet.g.alchemy.com/v2/...',
  },
  10: {
    chainId: 10,
    name: 'Optimism',
    privacyHub: '0x...opPrivacyHub',
    nullifierRegistry: '0x...opNullifierRegistry',
    rpcUrl: 'https://opt-mainnet.g.alchemy.com/v2/...',
  },
  42161: {
    chainId: 42161,
    name: 'Arbitrum',
    privacyHub: '0x...arbPrivacyHub',
    nullifierRegistry: '0x...arbNullifierRegistry',
    rpcUrl: 'https://arb-mainnet.g.alchemy.com/v2/...',
  },
};

// Initialize orchestrator
const orchestrator = new CrossChainPrivacyOrchestrator({
  chains: chainConfigs,
  privateKey: process.env.PRIVATE_KEY!,
  relayerType: 'layerzero', // or 'hyperlane'
});
```

## Step 2: Shield Funds (Source Chain)

```typescript
// Generate secret and commitment
const secret = orchestrator.generateSecret();
const amount = ethers.parseEther('1.0');

// Shield funds on Ethereum
const shieldResult = await orchestrator.shield({
  chainId: 1,
  amount,
  secret,
  recipient: myStealthAddress, // Optional: specify stealth address for withdrawal
});

console.log('Shield transaction:', shieldResult.txHash);
console.log('Commitment:', shieldResult.commitment);
console.log('Leaf index:', shieldResult.leafIndex);

// Store these securely!
const note = {
  commitment: shieldResult.commitment,
  secret: secret,
  amount: amount,
  leafIndex: shieldResult.leafIndex,
  sourceChain: 1,
};
```

## Step 3: Generate Cross-Chain Proof

```typescript
// Generate Merkle proof
const merkleProof = await orchestrator.getMerkleProof({
  chainId: 1,
  leafIndex: note.leafIndex,
});

// Derive nullifiers
const sourceNullifier = await orchestrator.deriveNullifier({
  secret: note.secret,
  commitment: note.commitment,
});

const crossDomainNullifier = await orchestrator.deriveCrossDomainNullifier({
  sourceNullifier,
  sourceChainId: 1,
  targetChainId: 10,
});

// Generate ZK proof
const zkProof = await orchestrator.generateCrossChainProof({
  commitment: note.commitment,
  amount: note.amount,
  secret: note.secret,
  merkleProof,
  sourceNullifier,
  targetNullifier: crossDomainNullifier,
  sourceChainId: 1,
  targetChainId: 10,
});

console.log('ZK Proof generated');
console.log('Public inputs:', zkProof.publicInputs);
```

## Step 4: Initiate Transfer

```typescript
// Spend on source chain
const spendResult = await orchestrator.initiatePrivateTransfer({
  sourceChainId: 1,
  targetChainId: 10,
  commitment: note.commitment,
  nullifier: sourceNullifier,
  proof: zkProof,
  amount: note.amount,
  recipient: recipientStealthAddress,
});

console.log('Transfer initiated:', spendResult.txHash);
console.log('Message ID:', spendResult.messageId);
```

## Step 5: Monitor Relay

```typescript
// Wait for relay across chains
const relayStatus = await orchestrator.waitForRelay({
  messageId: spendResult.messageId,
  sourceChainId: 1,
  targetChainId: 10,
  timeoutMs: 600000, // 10 minutes
});

console.log('Relay status:', relayStatus.status);
console.log('Target chain tx:', relayStatus.targetTxHash);
```

## Step 6: Claim on Destination

```typescript
// Claim on Optimism
const claimResult = await orchestrator.claimPrivateTransfer({
  targetChainId: 10,
  commitment: note.commitment,
  nullifier: crossDomainNullifier,
  proof: zkProof,
  amount: note.amount,
  recipient: recipientStealthAddress,
  relayProof: relayStatus.relayProof,
});

console.log('Claim transaction:', claimResult.txHash);
console.log('Private transfer complete!');
```

## Complete Example

```typescript
import {
  CrossChainPrivacyOrchestrator,
  PrivateTransferStatus,
} from '@pil/sdk';

async function privateTransferEthToOptimism(
  recipientStealthAddress: string,
  amountInEth: string
) {
  // Initialize
  const orchestrator = new CrossChainPrivacyOrchestrator({
    chains: chainConfigs,
    privateKey: process.env.PRIVATE_KEY!,
    relayerType: 'layerzero',
  });

  const amount = ethers.parseEther(amountInEth);

  try {
    // Full transfer flow
    const result = await orchestrator.executePrivateTransfer({
      sourceChainId: 1,
      targetChainId: 10,
      amount,
      recipient: recipientStealthAddress,
      onStatusChange: (status: PrivateTransferStatus) => {
        console.log(`Status: ${status.stage} - ${status.message}`);
      },
    });

    return {
      success: true,
      sourceChainTx: result.sourceTxHash,
      targetChainTx: result.targetTxHash,
      commitment: result.commitment,
      timeElapsed: result.timeElapsedMs,
    };
  } catch (error) {
    console.error('Private transfer failed:', error);
    throw error;
  }
}

// Usage
const result = await privateTransferEthToOptimism(
  'st:eth:0x...recipientStealthMeta...',
  '1.0'
);
console.log('Transfer complete:', result);
```

## Multi-Hop Transfers

For transfers through intermediate chains:

```typescript
// Ethereum -> Arbitrum -> Base
const hops = [
  { chainId: 1, amount: ethers.parseEther('1.0') },     // Shield on ETH
  { chainId: 42161, amount: ethers.parseEther('0.99') }, // Hop to Arbitrum
  { chainId: 8453, amount: ethers.parseEther('0.98') },  // Final on Base
];

const multiHopResult = await orchestrator.executeMultiHopTransfer({
  hops,
  recipient: recipientStealthAddress,
  onHopComplete: (hop, txHash) => {
    console.log(`Hop ${hop} complete: ${txHash}`);
  },
});
```

## Batch Transfers

Send to multiple recipients privately:

```typescript
const recipients = [
  { address: 'st:eth:0x...stealth1...', amount: ethers.parseEther('0.5') },
  { address: 'st:eth:0x...stealth2...', amount: ethers.parseEther('0.3') },
  { address: 'st:eth:0x...stealth3...', amount: ethers.parseEther('0.2') },
];

const batchResult = await orchestrator.executeBatchPrivateTransfer({
  sourceChainId: 1,
  targetChainId: 10,
  recipients,
  aggregateProofs: true, // Use Nova for proof aggregation
});
```

## Error Handling

```typescript
import {
  PrivacyTransferError,
  NullifierAlreadySpentError,
  InsufficientLiquidityError,
  RelayTimeoutError,
} from '@pil/sdk';

try {
  await orchestrator.executePrivateTransfer({ ... });
} catch (error) {
  if (error instanceof NullifierAlreadySpentError) {
    console.error('Double-spend attempt detected!');
  } else if (error instanceof InsufficientLiquidityError) {
    console.error('Not enough liquidity on target chain');
    console.error('Available:', error.availableLiquidity);
  } else if (error instanceof RelayTimeoutError) {
    console.error('Relay timed out. Message ID:', error.messageId);
    // Can retry claiming later
  } else {
    throw error;
  }
}
```

## Gas Optimization Tips

1. **Batch operations** - Use `executeBatchPrivateTransfer` for multiple sends
2. **Aggregate proofs** - Enable `aggregateProofs: true` for fewer on-chain verifications
3. **Choose optimal chains** - L2s have lower gas costs for ZK verification
4. **Use relayers** - Let relayers pay gas and reimburse with tokens

## Security Considerations

1. **Secure secret storage** - The secret is equivalent to funds ownership
2. **Verify recipient addresses** - Double-check stealth meta-addresses
3. **Wait for finality** - Ensure source chain transaction is final before claiming
4. **Monitor nullifiers** - Check nullifier status before transfers

## Supported Chains

| Chain | Chain ID | Status | Avg. Gas Cost |
|-------|----------|--------|---------------|
| Ethereum | 1 | ✅ | ~300k |
| Optimism | 10 | ✅ | ~50k |
| Arbitrum | 42161 | ✅ | ~60k |
| Base | 8453 | ✅ | ~45k |
| Polygon | 137 | ✅ | ~80k |
| zkSync | 324 | ✅ | ~40k |

## Next Steps

- [Privacy SDK Reference](./PRIVACY_SDK_TUTORIAL.md)
- [Stealth Address Deep Dive](./STEALTH_ADDRESSES.md)
- [Ring Signatures Guide](./RING_SIGNATURES.md)
- [Nullifier Management](./NULLIFIER_GUIDE.md)
