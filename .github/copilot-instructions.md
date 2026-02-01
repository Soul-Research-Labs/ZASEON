# Soul Project Context

Cross-chain ZK privacy middleware for confidential state transfer across L2 networks.

## Tech Stack
- **Solidity 0.8.20/0.8.22/0.8.24** with Foundry + Hardhat 3
- **ZK Circuits**: Noir (migrated from Circom)
- **Testing**: Foundry fuzz, Echidna, Certora, Halmos
- **Dependencies**: OpenZeppelin 5.4.0, viem 2.45+, ethers 6.16+
- **L2s**: Arbitrum, Optimism, Base, zkSync, Scroll, Linea, Polygon zkEVM

## Project Structure
```
contracts/     # Solidity (core, crosschain, privacy, security, pqc)
noir/          # Noir ZK circuits  
test/          # Foundry + Hardhat tests
sdk/           # TypeScript SDK
specs/         # K Framework, TLA+ specs
certora/       # Certora CVL specs
docs/          # Documentation
```

## Key Contracts
- `CrossChainProofHubV3` - Main proof aggregation hub with optimistic verification
- `ConfidentialStateContainerV3` - Encrypted state management with ZK proofs
- `ZKBoundStateLocks` - Cross-chain state locks with ZK unlock
- `SoulAtomicSwapV2` - Private atomic swaps with stealth addresses
- `NullifierRegistryV3` - Cross-domain nullifier tracking (CDNA)
- `DirectL2Messenger` - Direct L2-to-L2 messaging with chain ID validation

## Security Features
- Signature malleability protection on all ECDSA operations
- VRF verification for randomness in relayer selection
- Cross-chain replay protection via chain ID validation
- ReentrancyGuard on all state-changing functions
- Zero-address validation on critical setters

## Development Guidelines
- Follow Solidity style guide
- All new features need fuzz tests
- Security-critical code needs Certora specs
- Use existing patterns from `contracts/interfaces/`

## Commands
```bash
forge build && npx hardhat compile  # Build
forge test -vvv                      # Test (Foundry)
npx hardhat test                     # Test (Hardhat)
```

## Documentation
See `docs/GETTING_STARTED.md` for setup, `docs/INTEGRATION_GUIDE.md` for SDK usage.
