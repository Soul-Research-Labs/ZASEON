# Soul Protocol SDK — Quickstart Examples

Minimal TypeScript examples showing the most common Soul Protocol workflows.

## Prerequisites

```bash
npm install @soul-protocol/sdk viem
```

## Examples

| File                      | Description                                          |
| ------------------------- | ---------------------------------------------------- |
| `shielded-deposit.ts`     | Deposit ETH into a shielded pool with ZK commitments |
| `cross-chain-transfer.ts` | Private cross-chain transfer via the orchestrator    |
| `stealth-address.ts`      | Generate, publish, and scan stealth addresses        |
| `zk-proof.ts`             | Generate and relay a ZK proof using the ProverModule |

## Running

```bash
npx ts-node shielded-deposit.ts
```

> **Note:** These examples use Sepolia testnet addresses. Replace with your deployment addresses for other networks.
