# PIL Privacy Bug Bounty Program

Welcome to the Privacy Interoperability Layer (PIL) Bug Bounty Program. We're committed to ensuring the security of our privacy infrastructure and appreciate the help of security researchers in identifying vulnerabilities.

## Scope

### In-Scope Contracts

| Category | Contracts | Priority |
|----------|-----------|----------|
| **Core Privacy** | `StealthAddressRegistry.sol`, `RingCTModule.sol`, `NullifierManager.sol` | Critical |
| **Cross-Chain** | `CrossDomainNullifierSync.sol`, `PrivacyHub.sol`, `L2BridgeAdapters` | Critical |
| **ZK Verifiers** | All contracts in `contracts/verifiers/` | Critical |
| **Security Modules** | `MEVProtection.sol`, `FlashLoanGuard.sol`, `CircuitBreaker.sol` | High |
| **Governance** | `PILMultiSigGovernance.sol`, `PILUpgradeTimelock.sol` | High |
| **Bridge Adapters** | All L2/cross-chain adapters in `contracts/crosschain/` | High |

### Out of Scope

- Third-party contracts and integrations
- Frontend/UI vulnerabilities (unless they lead to contract exploits)
- Gas optimization issues without security impact
- Centralization concerns in admin keys (documented behavior)
- Issues in test/mock contracts
- Denial of service through dust amounts

## Severity Classification

### Critical ($25,000 - $100,000)

- Direct theft of funds from contracts
- Permanent freezing of funds
- Bypassing nullifier double-spend protection
- Breaking ZK proof verification (accepting invalid proofs)
- Breaking stealth address unlinkability
- Cross-chain message replay attacks
- Arbitrary code execution via upgrades

### High ($10,000 - $25,000)

- Privacy leaks revealing transaction linkability
- Temporary freezing of funds (>24 hours)
- Bypassing rate limits with significant impact
- Oracle manipulation leading to incorrect proofs
- Breaking ring signature anonymity set
- MEV extraction opportunities

### Medium ($2,500 - $10,000)

- Temporary DoS of critical functions
- Privacy degradation (reducing anonymity but not breaking it)
- Griefing attacks with economic impact
- Incorrect event emissions affecting indexers
- Access control issues for non-critical functions

### Low ($500 - $2,500)

- Minor gas optimizations with security relevance
- Missing input validation (without exploit path)
- Informational issues about best practices
- Documentation inconsistencies
- UI/UX issues that could lead to user error

## Reward Calculation

Base rewards are multiplied based on:

| Factor | Multiplier |
|--------|------------|
| First to report | 1.5x |
| PoC provided | 1.25x |
| Fix suggestion included | 1.1x |
| Affects mainnet | 2x |
| Affects multiple chains | 1.5x |

Maximum single payout: **$250,000**

## Submission Process

### 1. Report Discovery

Submit your finding to: **security@pilprotocol.io**

Include:
- Vulnerability title
- Affected contract(s) and function(s)
- Detailed description
- Step-by-step reproduction
- Impact assessment
- Proof of Concept (if available)
- Suggested fix (optional)

### 2. PGP Encryption (Recommended)

For sensitive vulnerabilities, encrypt your submission using our PGP key:

```
-----BEGIN PGP PUBLIC KEY BLOCK-----
[PGP Key will be published at pilprotocol.io/security.asc]
-----END PGP PUBLIC KEY BLOCK-----
```

### 3. Response Timeline

| Stage | Time |
|-------|------|
| Initial acknowledgment | 24 hours |
| Severity assessment | 72 hours |
| Fix timeline provided | 7 days |
| Bounty determination | 14 days |
| Payment processing | 30 days |

## On-Chain Bug Bounty Contract

We've deployed an on-chain bug bounty contract for transparent and trustless payments:

**Mainnet**: `TBD` (after audit)
**Sepolia**: `TBD` (deployed for testing)

### How It Works

1. **Report Submission**: Hash your report and submit on-chain
2. **Validation Period**: Team has 14 days to validate
3. **Payout**: Automatic payout after validation
4. **Dispute**: 7-day dispute window with arbitration

```solidity
// Submit report hash
function submitReport(bytes32 reportHash, Severity severity) external;

// Claim bounty after validation
function claimBounty(uint256 reportId) external;

// Check report status
function getReportStatus(uint256 reportId) external view returns (Status);
```

## Rules & Guidelines

### Do

✅ Test on testnets (Sepolia, L2 testnets)
✅ Use your own accounts and funds
✅ Report vulnerabilities privately first
✅ Give us reasonable time to fix (90 days max)
✅ Provide clear reproduction steps

### Don't

❌ Access others' private data
❌ Perform attacks on mainnet
❌ Publicly disclose before fix is deployed
❌ Submit duplicates of known issues
❌ Use automated scanners without manual verification
❌ Social engineering team members

## Known Issues

The following are known and accepted risks:

1. **Admin keys** - Multi-sig controlled, documented
2. **Upgrade timelock** - 48-hour delay by design
3. **Gas costs** - Privacy operations are expensive by design
4. **Circuit breaker** - Can pause contracts (emergency feature)

## Previous Findings

| ID | Severity | Status | Bounty |
|----|----------|--------|--------|
| PIB-001 | High | Fixed v1.1 | $15,000 |
| PIB-002 | Medium | Fixed v1.1 | $5,000 |
| PIB-003 | Low | Fixed v1.2 | $1,000 |

(This section will be updated as we process reports)

## Legal Safe Harbor

We will not pursue legal action against researchers who:

1. Make a good faith effort to avoid privacy violations, destruction of data, and interruption of services
2. Only interact with accounts they own or with explicit permission
3. Do not exploit a vulnerability beyond what's necessary to verify it
4. Report findings privately before any public disclosure
5. Do not engage in extortion

## Contact

- **Security Team**: security@pilprotocol.io
- **PGP Key**: pilprotocol.io/security.asc
- **Discord**: #security-reports (encrypted DMs enabled)
- **Telegram**: @PILSecurity (for urgent issues only)

## Acknowledgments

We maintain a Hall of Fame for researchers who help secure PIL:

### 🏆 Hall of Fame

| Researcher | Findings | Total Bounty |
|------------|----------|--------------|
| TBD | - | - |

---

**Program Version**: 1.0
**Last Updated**: January 2026
**Effective Date**: Upon mainnet launch
