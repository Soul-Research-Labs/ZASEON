# XRPL Integration Guide

> **Soul Protocol ↔ XRP Ledger Bridge**

This guide covers the XRP Ledger bridge adapter, enabling cross-chain transfers between Soul Protocol (EVM) and the XRP Ledger (XRPL).

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    Soul ↔ XRPL Bridge Architecture                      │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌───────────────────┐              ┌────────────────────────────┐     │
│  │   EVM Side        │              │   XRPL Side                │     │
│  │                   │              │                            │     │
│  │  ┌─────────────┐  │              │  ┌──────────────────────┐  │     │
│  │  │ wXRP Token  │  │              │  │ Bridge Multisig Acct │  │     │
│  │  │ (ERC-20)    │  │              │  │ (Federated Signers)  │  │     │
│  │  └──────┬──────┘  │              │  └──────────┬───────────┘  │     │
│  │         │         │   Relayer    │             │              │     │
│  │  ┌──────▼──────┐  │◄────────────►│  ┌──────────▼───────────┐  │     │
│  │  │ XRPL Bridge │  │  Network    │  │ Escrow / Payments    │  │     │
│  │  │ Adapter     │  │             │  │ (Native Primitives)  │  │     │
│  │  └──────┬──────┘  │              │  └──────────┬───────────┘  │     │
│  │         │         │              │             │              │     │
│  │  ┌──────▼──────┐  │              │  ┌──────────▼───────────┐  │     │
│  │  │ ZK Privacy  │  │              │  │ UNL Validators       │  │     │
│  │  │ Layer       │  │              │  │ (Ed25519 Consensus)  │  │     │
│  │  └─────────────┘  │              │  └──────────────────────┘  │     │
│  └───────────────────┘              └────────────────────────────┘     │
└─────────────────────────────────────────────────────────────────────────┘
```

## Key Concepts

### XRP Ledger Basics

| Concept | Description |
|---------|-------------|
| **Drops** | Smallest unit of XRP. 1 XRP = 1,000,000 drops |
| **Destination Tags** | 32-bit routing identifiers for multi-tenant accounts |
| **Escrow** | Native time-locked + crypto-conditioned contracts |
| **UNL** | Unique Node List — set of trusted validators |
| **SHAMap** | SHA-256 hash-based trie for transaction/state proofs |
| **Ed25519** | Signature algorithm used by XRPL validators |
| **Ripple Epoch** | Seconds since Jan 1, 2000 00:00:00 UTC |

### Bridge Components

| Component | Contract | Purpose |
|-----------|----------|---------|
| Bridge Adapter | `XRPLBridgeAdapter.sol` | Main bridge logic |
| Interface | `IXRPLBridgeAdapter.sol` | Bridge interface definition |
| Wrapped XRP | `MockWrappedXRP.sol` | ERC-20 representation of XRP |
| Validator Oracle | `MockXRPLValidatorOracle.sol` | UNL signature verification |

---

## Contract Details

### XRPLBridgeAdapter

**Inheritance:** `IXRPLBridgeAdapter`, `AccessControl`, `ReentrancyGuard`, `Pausable`

#### Roles

| Role | Permissions |
|------|------------|
| `DEFAULT_ADMIN_ROLE` | Full control, role management |
| `OPERATOR_ROLE` | Complete deposits, register private deposits, configure |
| `RELAYER_ROLE` | Initiate deposits, submit ledger headers, complete withdrawals |
| `GUARDIAN_ROLE` | Pause/unpause emergency controls |
| `TREASURY_ROLE` | Withdraw accumulated fees |

#### Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `DROPS_PER_XRP` | 1,000,000 | Drops per XRP |
| `MIN_DEPOSIT_DROPS` | 10,000,000 | Minimum deposit (10 XRP) |
| `MAX_DEPOSIT_DROPS` | 10,000,000,000,000 | Maximum deposit (10M XRP) |
| `BRIDGE_FEE_BPS` | 25 | Fee in basis points (0.25%) |
| `DEFAULT_ESCROW_TIMELOCK` | 86,400 | Default escrow lock (24h) |
| `MIN_ESCROW_TIMELOCK` | 3,600 | Minimum escrow lock (1h) |
| `MAX_ESCROW_TIMELOCK` | 2,592,000 | Maximum escrow lock (30d) |
| `WITHDRAWAL_REFUND_DELAY` | 172,800 | Refund waiting period (48h) |
| `DEFAULT_LEDGER_CONFIRMATIONS` | 32 | Required validated ledgers |

---

## Flows

### 1. Deposit (XRPL → EVM)

Transfer XRP from the XRPL to the EVM as wrapped XRP (wXRP).

```
XRPL Side                          EVM Side
──────────                          ────────
User sends XRP to                   Relayer monitors XRPL
bridge multisig account    ──►      for deposit transactions
        │                                    │
        │                           Relayer calls initiateXRPDeposit()
        │                           with SHAMap proof + attestations
        │                                    │
        │                           Operator calls completeXRPDeposit()
        │                           to mint wXRP to user
        │                                    │
        ▼                                    ▼
XRP locked in multisig              wXRP minted to evmRecipient
```

**SDK Example:**

```typescript
import { XRPLBridgeSDK } from '@soul/sdk/bridges/xrpl';

const bridge = new XRPLBridgeSDK(publicClient, walletClient);

// Monitor for deposit on XRPL side, then on EVM side:
const depositId = await bridge.initiateDeposit({
  xrplTxHash: '0x...',
  xrplSender: 'rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh',
  evmRecipient: '0x...',
  amountDrops: 50_000_000n, // 50 XRP
  destinationTag: 12345,
  ledgerIndex: 89012345,
});

// Complete deposit (operator)
await bridge.completeDeposit(depositId);
```

### 2. Withdrawal (EVM → XRPL)

Transfer wXRP from EVM back to native XRP on the XRPL.

```
EVM Side                            XRPL Side
────────                            ──────────
User calls initiateWithdrawal()     Relayer observes withdrawal
burns wXRP tokens          ──►      request on EVM
        │                                    │
        │                           Federated signers release
        │                           XRP from multisig to user
        │                                    │
        │                           Relayer calls completeWithdrawal()
        │                           with XRPL tx proof
        ▼                                    ▼
wXRP burned                         XRP sent to xrplRecipient
```

**SDK Example:**

```typescript
// Initiate withdrawal
const withdrawalId = await bridge.initiateWithdrawal({
  xrplRecipient: 'rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh',
  amountDrops: 25_000_000n, // 25 XRP
});

// If XRPL release fails after 48h, user can refund
await bridge.refundWithdrawal(withdrawalId);
```

### 3. Escrow (Atomic Swaps)

XRPL-style escrow with SHA-256 crypto-conditions for trustless atomic swaps.

```
Party A (EVM)                       Party B (XRPL)
─────────────                       ──────────────
Creates escrow with                 Creates matching escrow
condition = SHA256(preimage)        on XRPL with same condition
        │                                    │
        │ ← finishAfter passes ─►           │
        │                                    │
Party B reveals preimage   ──►      Party A uses preimage
on EVM to claim escrow              to claim XRPL escrow
        │                                    │
        ▼                                    ▼
ETH released to Party B             XRP released to Party A
```

**SDK Example:**

```typescript
// Create escrow
const { escrowId, condition } = await bridge.createEscrow({
  xrplParty: 'rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh',
  amountWei: parseEther('1'), // 1 ETH
  finishAfter: Math.floor(Date.now() / 1000) + 7200,  // 2h from now
  cancelAfter: Math.floor(Date.now() / 1000) + 93600, // 26h from now
});

// Finish escrow with preimage
await bridge.finishEscrow(escrowId, preimage);

// Or cancel after cancelAfter (refunds to creator)
await bridge.cancelEscrow(escrowId);
```

### 4. Private Deposit (ZK Privacy)

Register a deposit with zero-knowledge privacy (commitment + nullifier).

```typescript
// After a deposit is completed, register it privately
await bridge.registerPrivateDeposit({
  depositId: '0x...',
  commitment: '0x...',  // Pedersen commitment
  nullifier: '0x...',   // Unique nullifier
  zkProof: '0x...',     // ZK proof bytes
});
```

---

## Deployment

### Prerequisites

```bash
# Install dependencies
npm install

# Build contracts
forge build && npx hardhat compile
```

### Deploy to Local Network

```bash
# Start local node
anvil &

# Deploy
npx hardhat run scripts/deploy/deploy-xrpl-bridge.ts --network localhost
```

### Deploy to Testnet

```bash
# Set environment variables
export XRPL_MULTISIG_ACCOUNT="0xAABBCCDDEEFF00112233445566778899AABBCCDD"
export XRPL_MIN_SIGNATURES=3
export XRPL_LEDGER_CONFIRMATIONS=32
export RELAYER_ADDRESS="0x..."
export GUARDIAN_ADDRESS="0x..."
export TREASURY_ADDRESS="0x..."

# Deploy to Sepolia
npx hardhat run scripts/deploy/deploy-xrpl-bridge.ts --network sepolia
```

### Deploy with Existing Tokens

```bash
# If you already have a wXRP token and oracle deployed
export XRPL_WRAPPED_XRP_ADDRESS="0x..."
export XRPL_VALIDATOR_ORACLE="0x..."

npx hardhat run scripts/deploy/deploy-xrpl-bridge.ts --network sepolia
```

---

## Testing

### Foundry Fuzz Tests

```bash
# Run all XRPL bridge fuzz tests
forge test --match-contract XRPLBridgeFuzz -vvv

# Run specific test
forge test --match-test testFuzz_feeCalculation -vvv

# Run with extended fuzzing
forge test --match-contract XRPLBridgeFuzz --fuzz-runs 10000
```

### Hardhat Integration Tests

```bash
# Run XRPL integration tests
npx hardhat test test/XRPLBridgeAdapter.test.ts
```

### Formal Verification (Certora)

```bash
# Run Certora verification
certoraRun certora/conf/verify_xrpl_bridge.conf
```

---

## Security Considerations

### Validator Attestations

The bridge relies on XRPL validator attestations to verify ledger validity:

- **Minimum signatures**: Configurable (recommended ≥80% of UNL)
- **Ed25519 verification**: Delegated to the Validator Oracle contract
- **UNL management**: Oracle maintains the current UNL set

### Replay Protection

- **XRPL tx hashes**: Each XRPL transaction hash can only be used once
- **Nullifiers**: ZK privacy nullifiers are permanently marked after use
- **Nonce monotonicity**: All nonces (deposit, withdrawal, escrow) only increase

### Timelock Security

- **Escrow timelocks**: Minimum 1 hour, maximum 30 days
- **Withdrawal refund**: 48-hour delay before refund is available
- **Ledger confirmations**: Default 32 validated ledgers required

### Emergency Controls

- **Pause**: Guardian can pause all operations immediately
- **Fee withdrawal**: Treasury can collect accumulated fees
- **Access control**: Role-based permissions for all privileged operations

---

## API Reference

### Write Functions

| Function | Role | Description |
|----------|------|-------------|
| `configure()` | OPERATOR | Set bridge parameters |
| `initiateXRPDeposit()` | RELAYER | Submit deposit with proofs |
| `completeXRPDeposit()` | OPERATOR | Mint wXRP to recipient |
| `initiateWithdrawal()` | Any | Burn wXRP for XRPL release |
| `completeWithdrawal()` | RELAYER | Confirm XRPL release |
| `refundWithdrawal()` | Any | Refund after 48h timeout |
| `createEscrow()` | Any | Create crypto-conditioned escrow |
| `finishEscrow()` | Any | Claim escrow with preimage |
| `cancelEscrow()` | Any | Cancel escrow after timeout |
| `registerPrivateDeposit()` | OPERATOR | Register ZK private deposit |
| `submitLedgerHeader()` | RELAYER | Submit validated ledger header |
| `pause()` / `unpause()` | GUARDIAN | Emergency controls |
| `withdrawFees()` | TREASURY | Collect bridge fees |
| `setTreasury()` | ADMIN | Set fee recipient |

### View Functions

| Function | Description |
|----------|-------------|
| `getDeposit(bytes32)` | Get deposit details |
| `getWithdrawal(bytes32)` | Get withdrawal details |
| `getEscrow(bytes32)` | Get escrow details |
| `getLedgerHeader(uint256)` | Get ledger header |
| `getUserDeposits(address)` | Get user's deposit IDs |
| `getUserWithdrawals(address)` | Get user's withdrawal IDs |
| `getUserEscrows(address)` | Get user's escrow IDs |
| `getBridgeStats()` | Get aggregate statistics |

### Events

| Event | Emitted When |
|-------|-------------|
| `XRPDepositInitiated` | Deposit proof submitted |
| `XRPDepositCompleted` | wXRP minted to recipient |
| `XRPWithdrawalInitiated` | User burns wXRP |
| `XRPWithdrawalCompleted` | XRPL release confirmed |
| `XRPWithdrawalRefunded` | Withdrawal refunded after timeout |
| `EscrowCreated` | New escrow created |
| `EscrowFinished` | Escrow claimed with preimage |
| `EscrowCancelled` | Escrow cancelled after timeout |
| `LedgerHeaderSubmitted` | New validated ledger header |
| `PrivateDepositRegistered` | ZK privacy deposit registered |
| `FeesWithdrawn` | Fees collected by treasury |
| `BridgeConfigured` | Bridge parameters updated |

---

## Integration Checklist

- [ ] Deploy `MockWrappedXRP` (or use production wXRP token)
- [ ] Deploy `MockXRPLValidatorOracle` (or use production oracle)
- [ ] Deploy `XRPLBridgeAdapter`
- [ ] Configure bridge with multisig account and parameters
- [ ] Grant `MINTER_ROLE` on wXRP to bridge adapter
- [ ] Grant roles (RELAYER, GUARDIAN, TREASURY)
- [ ] Set up relayer infrastructure for XRPL monitoring
- [ ] Register XRPL validators in the oracle
- [ ] Submit initial ledger headers
- [ ] Test deposit/withdrawal flow end-to-end
- [ ] Enable ZK privacy features
- [ ] Set up monitoring and alerting
