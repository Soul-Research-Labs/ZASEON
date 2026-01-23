# Privacy SDK Tutorial - Complete Developer Guide

Welcome to the PIL Privacy SDK! This guide will walk you through implementing privacy features in your application, from basic stealth addresses to complex cross-chain private transfers.

## Table of Contents

1. [Getting Started](#getting-started)
2. [Stealth Addresses](#stealth-addresses)
3. [Ring Confidential Transactions](#ring-confidential-transactions)
4. [Cross-Domain Nullifiers](#cross-domain-nullifiers)
5. [Private Relayer Network](#private-relayer-network)
6. [Multi-Chain Privacy](#multi-chain-privacy)
7. [Advanced Topics](#advanced-topics)

---

## Getting Started

### Installation

```bash
npm install @pil/sdk
# or
yarn add @pil/sdk
```

### Quick Start

```typescript
import { 
  StealthAddressClient, 
  RingCTClient, 
  NullifierClient,
  PrivacyHubClient 
} from '@pil/sdk/privacy';
import { ethers } from 'ethers';

// Initialize provider
const provider = new ethers.JsonRpcProvider('https://sepolia.infura.io/v3/YOUR_KEY');
const signer = new ethers.Wallet('YOUR_PRIVATE_KEY', provider);

// Initialize privacy clients
const stealthClient = new StealthAddressClient(
  '0x...stealthRegistryAddress',
  signer
);
```

---

## Stealth Addresses

Stealth addresses allow you to receive funds without revealing your identity on-chain. Each payment generates a unique, unlinkable address.

### Generating Your Keys

```typescript
import { generateStealthMetaAddress, StealthKeys } from '@pil/sdk/privacy';

// Generate a new stealth meta-address (do this once)
const keys: StealthKeys = generateStealthMetaAddress();

console.log('Spending Public Key:', keys.spendingPublicKey);
console.log('Viewing Public Key:', keys.viewingPublicKey);
console.log('Stealth Meta-Address:', keys.metaAddress);

// IMPORTANT: Store your private keys securely!
// keys.spendingPrivateKey
// keys.viewingPrivateKey
```

### Receiving Payments (Recipient)

Share your stealth meta-address publicly. Senders will use it to generate unique payment addresses.

```typescript
// Your public stealth meta-address (safe to share)
const myMetaAddress = 'st:eth:0x...spendingPub...viewingPub';

// The sender will generate a unique stealth address for you
// You don't need to do anything until you want to scan for payments
```

### Scanning for Payments

```typescript
import { scanForStealthPayments } from '@pil/sdk/privacy';

// Scan the blockchain for payments to your stealth addresses
const payments = await stealthClient.scan({
  viewingPrivateKey: keys.viewingPrivateKey,
  startBlock: 1000000,
  endBlock: 'latest',
});

for (const payment of payments) {
  console.log(`Found payment at ${payment.stealthAddress}`);
  console.log(`Amount: ${ethers.formatEther(payment.amount)} ETH`);
  console.log(`View Tag: ${payment.viewTag}`);
}
```

### Spending from Stealth Address

```typescript
// Derive the private key for a specific stealth address
const spendingKey = await stealthClient.deriveStealthPrivateKey({
  spendingPrivateKey: keys.spendingPrivateKey,
  ephemeralPublicKey: payment.ephemeralPublicKey,
});

// Create a wallet with the derived key
const stealthWallet = new ethers.Wallet(spendingKey, provider);

// Now you can spend from this address
const tx = await stealthWallet.sendTransaction({
  to: recipientAddress,
  value: payment.amount,
});
```

### Sending Payments (Sender)

```typescript
// Parse recipient's stealth meta-address
const recipientMeta = parseStealthMetaAddress('st:eth:0x...');

// Generate a unique stealth address for this payment
const { stealthAddress, ephemeralPublicKey, viewTag } = 
  await stealthClient.generateStealthAddress({
    spendingPublicKey: recipientMeta.spendingPublicKey,
    viewingPublicKey: recipientMeta.viewingPublicKey,
  });

console.log(`Send funds to: ${stealthAddress}`);
console.log(`Ephemeral Key: ${ephemeralPublicKey}`);
console.log(`View Tag: ${viewTag}`);

// Send funds to the stealth address
const tx = await signer.sendTransaction({
  to: stealthAddress,
  value: ethers.parseEther('1.0'),
});

// Announce the payment (so recipient can find it)
await stealthClient.announce({
  ephemeralPublicKey,
  stealthAddress,
  viewTag,
});
```

---

## Ring Confidential Transactions

RingCT allows you to hide both the sender (among a ring of possible senders) and the amount transferred.

### Creating a RingCT Transaction

```typescript
import { RingCTClient, selectDecoys } from '@pil/sdk/privacy';

const ringCTClient = new RingCTClient(
  '0x...ringCTAddress',
  signer
);

// Your input (UTXO you own)
const myInput = {
  commitment: '0x...commitment',
  amount: ethers.parseEther('1.0'),
  blindingFactor: '0x...blinding',
  keyImage: await ringCTClient.computeKeyImage(privateKey),
};

// Select decoys (other UTXOs to hide among)
const decoys = await selectDecoys({
  ringSize: 11, // Standard ring size
  excludeKeyImages: [myInput.keyImage],
  client: ringCTClient,
});

// Create the ring (your input + decoys)
const ring = [myInput, ...decoys];

// Define outputs
const outputs = [
  { recipient: recipientAddress, amount: ethers.parseEther('0.9') },
  { recipient: signer.address, amount: ethers.parseEther('0.09') }, // Change
];
// Fee: 0.01 ETH

// Create the RingCT transaction
const ringCTTx = await ringCTClient.createTransaction({
  inputs: [myInput],
  ring,
  outputs,
  fee: ethers.parseEther('0.01'),
});

// Submit
const tx = await ringCTClient.submitTransaction(ringCTTx);
console.log('RingCT Transaction:', tx.hash);
```

### Verifying a RingCT Transaction

```typescript
const isValid = await ringCTClient.verify({
  keyImages: ringCTTx.keyImages,
  inputCommitments: ringCTTx.inputCommitments,
  outputCommitments: ringCTTx.outputCommitments,
  signature: ringCTTx.signature,
  pseudoOutputCommitment: ringCTTx.pseudoOutputCommitment,
});

console.log('Transaction valid:', isValid);
```

---

## Cross-Domain Nullifiers

Nullifiers prevent double-spending across chains while maintaining privacy.

### Consuming a Nullifier

```typescript
import { NullifierClient } from '@pil/sdk/privacy';

const nullifierClient = new NullifierClient(
  '0x...nullifierManagerAddress',
  signer
);

// Derive nullifier from your secret
const nullifier = await nullifierClient.deriveNullifier({
  secret: mySecret,
  commitment: myCommitment,
});

// Register the domain (one-time)
const domainId = await nullifierClient.registerDomain({
  chainId: 1,
  appId: '0x...myAppId',
  epochEnd: Math.floor(Date.now() / 1000) + 86400 * 365, // 1 year
});

// Consume the nullifier
const tx = await nullifierClient.consumeNullifier({
  nullifier,
  domainId,
  commitment: myCommitment,
});

console.log('Nullifier consumed:', tx.hash);
```

### Cross-Chain Nullifier Derivation

```typescript
// After spending on Chain A, derive nullifier for Chain B
const crossDomainNullifier = await nullifierClient.deriveCrossDomainNullifier({
  sourceNullifier: nullifierOnChainA,
  sourceDomain: domainIdChainA,
  targetDomain: domainIdChainB,
});

// Use on Chain B to prevent replay
await nullifierClientChainB.consumeNullifier({
  nullifier: crossDomainNullifier,
  domainId: domainIdChainB,
});
```

---

## Private Relayer Network

Use relayers to submit transactions without revealing your IP or paying gas directly.

### Finding Relayers

```typescript
import { RelayerClient } from '@pil/sdk/privacy';

const relayerClient = new RelayerClient(
  '0x...relayerNetworkAddress',
  provider // Note: read-only, no signer needed for queries
);

// Get available relayers sorted by reputation and fee
const relayers = await relayerClient.getActiveRelayers({
  minStake: ethers.parseEther('10'),
  minReputation: 80,
  sortBy: 'fee',
});

console.log('Top relayer:', relayers[0]);
```

### Submitting via Relayer

```typescript
// Prepare your private transaction
const privateTx = {
  proof: zkProof,
  publicInputs: inputs,
  commitment: commitment,
  nullifier: nullifier,
};

// Commit to prevent front-running
const commitHash = await relayerClient.computeCommitHash(privateTx);

// Request relay with commit-reveal
const relayRequest = await relayerClient.requestRelay({
  relayer: relayers[0].address,
  commitHash,
  maxFee: ethers.parseEther('0.01'),
});

// Wait for commitment to be recorded
await relayRequest.waitForCommit();

// Reveal and execute
const tx = await relayerClient.revealAndExecute({
  requestId: relayRequest.id,
  transaction: privateTx,
});

console.log('Relayed transaction:', tx.hash);
```

---

## Multi-Chain Privacy

Maintain privacy across multiple chains with the Privacy Hub.

### Cross-Chain Private Transfer

```typescript
import { PrivacyHubClient } from '@pil/sdk/privacy';

const privacyHubEth = new PrivacyHubClient(
  '0x...privacyHubEthereum',
  signerEth
);

const privacyHubOp = new PrivacyHubClient(
  '0x...privacyHubOptimism',
  signerOp
);

// Step 1: Create commitment on Ethereum
const commitment = await privacyHubEth.createCommitment({
  amount: ethers.parseEther('1.0'),
  recipient: recipientStealthAddress,
  secret: mySecret,
});

// Step 2: Generate cross-chain proof
const proof = await privacyHubEth.generateCrossChainProof({
  commitment,
  sourceChain: 1,
  targetChain: 10, // Optimism
});

// Step 3: Submit to source chain
const sourceTx = await privacyHubEth.initiateTransfer({
  commitment,
  proof,
  targetChain: 10,
});

// Step 4: Wait for relay
const relayProof = await privacyHubEth.waitForRelay(sourceTx.hash);

// Step 5: Claim on Optimism
const claimTx = await privacyHubOp.claimTransfer({
  commitment,
  proof: relayProof,
  secret: mySecret,
});

console.log('Private cross-chain transfer complete!');
console.log('Source tx:', sourceTx.hash);
console.log('Claim tx:', claimTx.hash);
```

---

## Advanced Topics

### Triptych Signatures (Large Rings)

For larger anonymity sets, use Triptych signatures with O(log n) proof size:

```typescript
import { TriptychClient } from '@pil/sdk/privacy';

const triptychClient = new TriptychClient(
  '0x...triptychAddress',
  signer
);

// Create ring with 256 members
const largeRing = await triptychClient.buildRing({ size: 256 });

// Sign with logarithmic proof size
const signature = await triptychClient.sign({
  message: messageHash,
  ring: largeRing,
  signerIndex: myIndex,
  privateKey: myPrivateKey,
});

// Proof size is O(log 256) = O(8), not O(256)
console.log('Proof size:', signature.proof.length);
```

### Nova Recursive Proofs

Aggregate multiple proofs into one:

```typescript
import { NovaClient } from '@pil/sdk/privacy';

const novaClient = new NovaClient(
  '0x...novaVerifierAddress',
  signer
);

// Aggregate multiple proofs
const aggregatedProof = await novaClient.aggregate([
  proof1,
  proof2,
  proof3,
  // ... up to 32 proofs
]);

// Verify once instead of N times
const isValid = await novaClient.verify(aggregatedProof);
```

### Seraphis Addressing (Advanced Privacy)

Three-key system for maximum privacy:

```typescript
import { SeraphisClient } from '@pil/sdk/privacy';

const seraphisClient = new SeraphisClient(
  '0x...seraphisAddress',
  signer
);

// Generate Seraphis keys
const seraphisKeys = seraphisClient.generateKeys();
// - k_vb: View-balance key (see balance)
// - k_m: Master key (generate subaddresses)
// - k_gi: Generate-image key (for key images)

// Generate subaddresses
const subaddress = seraphisClient.generateSubaddress({
  masterKey: seraphisKeys.k_m,
  accountIndex: 0,
  subaddressIndex: 1,
});

// Create private transfer with Grootle proofs
const transfer = await seraphisClient.createTransfer({
  inputs: myInputs,
  outputs: outputs,
  keys: seraphisKeys,
});
```

---

## Best Practices

1. **Never reuse ephemeral keys** - Generate a new ephemeral key for each stealth address
2. **Use appropriate ring sizes** - Larger rings = more privacy but higher gas costs
3. **Verify proofs locally** before submitting to avoid wasted gas
4. **Use relayers** for maximum privacy (hides your IP)
5. **Cross-chain transfers** require careful nullifier management

## Support

- Documentation: https://docs.pilprotocol.io/privacy
- Discord: https://discord.gg/pilprotocol
- Security issues: security@pilprotocol.io
