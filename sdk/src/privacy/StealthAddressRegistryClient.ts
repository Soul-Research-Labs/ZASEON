/**
 * @title StealthAddressRegistryClient
 * @description Full-featured SDK client for the StealthAddressRegistry contract.
 *
 * Covers the complete on-chain API:
 *   - Meta-address registration, status updates, and revocation
 *   - Stealth address derivation (single + dual-key)
 *   - Payment announcements (operator + self-service)
 *   - Cross-chain stealth derivation
 *   - Batch scanning and view-tag indexed lookups
 *   - Ownership verification
 *   - Admin operations (verifier config, fee withdrawal)
 *
 * @see contracts/privacy/StealthAddressRegistry.sol
 */

import {
  type PublicClient,
  type WalletClient,
  type Hex,
  type Address,
  getContract,
} from "viem";
import type { ViemReadonlyContract } from "../types/contracts";

// ─── Enums ──────────────────────────────────────────────────────────

/** Elliptic curve types supported by the registry */
export enum CurveType {
  SECP256K1 = 0,
  ED25519 = 1,
  BLS12_381 = 2,
  PALLAS = 3,
  VESTA = 4,
  BN254 = 5,
}

/** Key lifecycle status */
export enum KeyStatus {
  INACTIVE = 0,
  ACTIVE = 1,
  REVOKED = 2,
}

// ─── Types ──────────────────────────────────────────────────────────

/** On-chain stealth meta-address record */
export interface StealthMetaAddressRecord {
  spendingPubKey: Hex;
  viewingPubKey: Hex;
  curveType: CurveType;
  status: KeyStatus;
  registeredAt: bigint;
  schemeId: bigint;
}

/** Announcement record */
export interface AnnouncementRecord {
  schemeId: Hex;
  stealthAddress: Address;
  ephemeralPubKey: Hex;
  viewTag: Hex;
  metadata: Hex;
  timestamp: bigint;
  chainId: bigint;
}

/** Dual-key stealth record */
export interface DualKeyStealthRecord {
  spendingPubKeyHash: Hex;
  viewingPubKeyHash: Hex;
  stealthAddressHash: Hex;
  ephemeralPubKeyHash: Hex;
  sharedSecretHash: Hex;
  derivedAddress: Address;
  chainId: bigint;
}

/** Cross-chain stealth binding */
export interface CrossChainStealthBinding {
  sourceStealthKey: Hex;
  destStealthKey: Hex;
  sourceChainId: bigint;
  destChainId: bigint;
  derivationProof: Hex;
  timestamp: bigint;
}

/** Pool statistics */
export interface RegistryStats {
  registeredCount: bigint;
  announcementCount: bigint;
  crossChainDerivationCount: bigint;
}

// ─── ABI ────────────────────────────────────────────────────────────

const STEALTH_ADDRESS_REGISTRY_ABI = [
  // ─── Registration ─────────────────────────────────────────
  {
    name: "registerMetaAddress",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "spendingPubKey", type: "bytes" },
      { name: "viewingPubKey", type: "bytes" },
      { name: "curveType", type: "uint8" },
      { name: "schemeId", type: "uint256" },
    ],
    outputs: [],
  },
  {
    name: "updateMetaAddressStatus",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "newStatus", type: "uint8" }],
    outputs: [],
  },
  {
    name: "revokeMetaAddress",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [],
    outputs: [],
  },
  // ─── Derivation ───────────────────────────────────────────
  {
    name: "deriveStealthAddress",
    type: "function",
    stateMutability: "view",
    inputs: [
      { name: "recipient", type: "address" },
      { name: "ephemeralPubKey", type: "bytes" },
      { name: "sharedSecretHash", type: "bytes32" },
    ],
    outputs: [
      { name: "stealthAddress", type: "address" },
      { name: "viewTag", type: "bytes1" },
    ],
  },
  {
    name: "computeDualKeyStealth",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "spendingPubKeyHash", type: "bytes32" },
      { name: "viewingPubKeyHash", type: "bytes32" },
      { name: "ephemeralPrivKeyHash", type: "bytes32" },
      { name: "chainId", type: "uint256" },
    ],
    outputs: [
      { name: "stealthHash", type: "bytes32" },
      { name: "derivedAddress", type: "address" },
    ],
  },
  {
    name: "deriveCrossChainStealth",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "sourceStealthKey", type: "bytes32" },
      { name: "destChainId", type: "uint256" },
      { name: "derivationProof", type: "bytes" },
    ],
    outputs: [{ name: "destKey", type: "bytes32" }],
  },
  // ─── Announcements ────────────────────────────────────────
  {
    name: "announce",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "schemeId", type: "uint256" },
      { name: "stealthAddress", type: "address" },
      { name: "ephemeralPubKey", type: "bytes" },
      { name: "viewTag", type: "bytes" },
      { name: "metadata", type: "bytes" },
    ],
    outputs: [],
  },
  {
    name: "announcePrivate",
    type: "function",
    stateMutability: "payable",
    inputs: [
      { name: "schemeId", type: "uint256" },
      { name: "stealthAddress", type: "address" },
      { name: "ephemeralPubKey", type: "bytes" },
      { name: "viewTag", type: "bytes" },
      { name: "metadata", type: "bytes" },
    ],
    outputs: [],
  },
  // ─── Scanning / Ownership ─────────────────────────────────
  {
    name: "getAnnouncementsByViewTag",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "viewTag", type: "bytes1" }],
    outputs: [{ name: "addresses", type: "address[]" }],
  },
  {
    name: "checkStealthOwnership",
    type: "function",
    stateMutability: "view",
    inputs: [
      { name: "stealthAddress", type: "address" },
      { name: "viewingPrivKeyHash", type: "bytes32" },
      { name: "spendingPubKeyHash", type: "bytes32" },
    ],
    outputs: [{ name: "isOwner", type: "bool" }],
  },
  {
    name: "batchScan",
    type: "function",
    stateMutability: "view",
    inputs: [
      { name: "viewingPrivKeyHash", type: "bytes32" },
      { name: "spendingPubKeyHash", type: "bytes32" },
      { name: "candidates", type: "address[]" },
    ],
    outputs: [{ name: "owned", type: "address[]" }],
  },
  // ─── Queries ──────────────────────────────────────────────
  {
    name: "getMetaAddress",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "owner", type: "address" }],
    outputs: [
      {
        name: "",
        type: "tuple",
        components: [
          { name: "spendingPubKey", type: "bytes" },
          { name: "viewingPubKey", type: "bytes" },
          { name: "curveType", type: "uint8" },
          { name: "status", type: "uint8" },
          { name: "registeredAt", type: "uint256" },
          { name: "schemeId", type: "uint256" },
        ],
      },
    ],
  },
  {
    name: "getAnnouncement",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "stealthAddress", type: "address" }],
    outputs: [
      {
        name: "",
        type: "tuple",
        components: [
          { name: "schemeId", type: "bytes32" },
          { name: "stealthAddress", type: "address" },
          { name: "ephemeralPubKey", type: "bytes" },
          { name: "viewTag", type: "bytes" },
          { name: "metadata", type: "bytes" },
          { name: "timestamp", type: "uint256" },
          { name: "chainId", type: "uint256" },
        ],
      },
    ],
  },
  {
    name: "getDualKeyRecord",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "stealthHash", type: "bytes32" }],
    outputs: [
      {
        name: "",
        type: "tuple",
        components: [
          { name: "spendingPubKeyHash", type: "bytes32" },
          { name: "viewingPubKeyHash", type: "bytes32" },
          { name: "stealthAddressHash", type: "bytes32" },
          { name: "ephemeralPubKeyHash", type: "bytes32" },
          { name: "sharedSecretHash", type: "bytes32" },
          { name: "derivedAddress", type: "address" },
          { name: "chainId", type: "uint256" },
        ],
      },
    ],
  },
  {
    name: "getCrossChainBinding",
    type: "function",
    stateMutability: "view",
    inputs: [
      { name: "sourceKey", type: "bytes32" },
      { name: "destKey", type: "bytes32" },
    ],
    outputs: [
      {
        name: "",
        type: "tuple",
        components: [
          { name: "sourceStealthKey", type: "bytes32" },
          { name: "destStealthKey", type: "bytes32" },
          { name: "sourceChainId", type: "uint256" },
          { name: "destChainId", type: "uint256" },
          { name: "derivationProof", type: "bytes" },
          { name: "timestamp", type: "uint256" },
        ],
      },
    ],
  },
  {
    name: "getRegisteredAddressCount",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "uint256" }],
  },
  {
    name: "getStats",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [
      { name: "registered", type: "uint256" },
      { name: "announcements", type: "uint256" },
      { name: "crossChainDerivations", type: "uint256" },
    ],
  },
  {
    name: "totalAnnouncements",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "uint256" }],
  },
  // ─── Admin ────────────────────────────────────────────────
  {
    name: "setDerivationVerifier",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "_verifier", type: "address" }],
    outputs: [],
  },
  {
    name: "withdrawFees",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "recipient", type: "address" },
      { name: "amount", type: "uint256" },
    ],
    outputs: [],
  },
  // ─── Events ───────────────────────────────────────────────
  {
    name: "MetaAddressRegistered",
    type: "event",
    inputs: [
      { name: "owner", type: "address", indexed: true },
      { name: "spendingPubKey", type: "bytes", indexed: false },
      { name: "viewingPubKey", type: "bytes", indexed: false },
      { name: "curveType", type: "uint8", indexed: false },
      { name: "schemeId", type: "uint256", indexed: false },
    ],
  },
  {
    name: "MetaAddressUpdated",
    type: "event",
    inputs: [
      { name: "owner", type: "address", indexed: true },
      { name: "newStatus", type: "uint8", indexed: false },
    ],
  },
  {
    name: "StealthAnnouncement",
    type: "event",
    inputs: [
      { name: "schemeId", type: "bytes32", indexed: true },
      { name: "stealthAddress", type: "address", indexed: true },
      { name: "caller", type: "address", indexed: true },
      { name: "ephemeralPubKey", type: "bytes", indexed: false },
      { name: "viewTag", type: "bytes", indexed: false },
      { name: "metadata", type: "bytes", indexed: false },
    ],
  },
  {
    name: "CrossChainStealthDerived",
    type: "event",
    inputs: [
      { name: "sourceKey", type: "bytes32", indexed: true },
      { name: "destKey", type: "bytes32", indexed: true },
      { name: "sourceChainId", type: "uint256", indexed: false },
      { name: "destChainId", type: "uint256", indexed: false },
    ],
  },
  {
    name: "DualKeyStealthGenerated",
    type: "event",
    inputs: [
      { name: "stealthHash", type: "bytes32", indexed: true },
      { name: "derivedAddress", type: "address", indexed: true },
      { name: "chainId", type: "uint256", indexed: false },
    ],
  },
] as const;

// ─── Client ─────────────────────────────────────────────────────────

/**
 * Full-featured client for on-chain StealthAddressRegistry interactions.
 *
 * Complements the existing `StealthAddressClient` (which provides off-chain
 * key generation and simplified helpers) with the complete contract API:
 * cross-chain derivation, dual-key stealth, batch scanning, view-tag indexing,
 * ownership checks, and admin operations.
 *
 * @example
 * ```ts
 * const client = new StealthAddressRegistryClient(
 *   '0x52f8...32cc',
 *   publicClient,
 *   walletClient,
 * );
 *
 * // Register meta-address
 * await client.registerMetaAddress(spendingKey, viewingKey, CurveType.SECP256K1, 1n);
 *
 * // Derive a one-time stealth address for a recipient
 * const { stealthAddress, viewTag } = await client.deriveStealthAddress(
 *   recipientAddr, ephemeralPubKey, sharedSecretHash,
 * );
 *
 * // Batch-scan for owned stealth addresses
 * const owned = await client.batchScan(viewingPrivKeyHash, spendingPubKeyHash, candidates);
 * ```
 */
export class StealthAddressRegistryClient {
  private readonly contract: ViemReadonlyContract;
  private readonly walletClient?: WalletClient;
  public readonly address: Address;

  constructor(
    contractAddress: Address,
    publicClient: PublicClient,
    walletClient?: WalletClient,
  ) {
    this.address = contractAddress;
    this.walletClient = walletClient;

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const abi = STEALTH_ADDRESS_REGISTRY_ABI as any;
    this.contract = getContract({
      address: contractAddress,
      abi,
      client: { public: publicClient, wallet: walletClient },
    }) as unknown as ViemReadonlyContract;
  }

  // ─── Registration ───────────────────────────────────────────

  /**
   * Register a stealth meta-address (spending + viewing keys) for the connected wallet.
   * @param spendingPubKey Spending public key bytes
   * @param viewingPubKey  Viewing public key bytes
   * @param curveType      Elliptic curve type
   * @param schemeId       Stealth address scheme identifier (ERC-5564)
   * @returns Transaction hash
   */
  async registerMetaAddress(
    spendingPubKey: Hex,
    viewingPubKey: Hex,
    curveType: CurveType,
    schemeId: bigint,
  ): Promise<Hex> {
    this.requireWallet();
    return this.contract.write!.registerMetaAddress([
      spendingPubKey,
      viewingPubKey,
      curveType,
      schemeId,
    ]) as Promise<Hex>;
  }

  /**
   * Update the status of the caller's meta-address (ACTIVE ↔ INACTIVE).
   * @param newStatus Target status
   * @returns Transaction hash
   */
  async updateMetaAddressStatus(newStatus: KeyStatus): Promise<Hex> {
    this.requireWallet();
    return this.contract.write!.updateMetaAddressStatus([
      newStatus,
    ]) as Promise<Hex>;
  }

  /**
   * Permanently revoke the caller's meta-address. Irreversible.
   * @returns Transaction hash
   */
  async revokeMetaAddress(): Promise<Hex> {
    this.requireWallet();
    return this.contract.write!.revokeMetaAddress([]) as Promise<Hex>;
  }

  // ─── Derivation ─────────────────────────────────────────────

  /**
   * Derive a one-time stealth address for a recipient using DKSAP.
   * @param recipient      Recipient address (must have a registered meta-address)
   * @param ephemeralPubKey Ephemeral public key generated per-payment
   * @param sharedSecretHash Hash of the DH shared secret
   * @returns Stealth address and view tag
   */
  async deriveStealthAddress(
    recipient: Address,
    ephemeralPubKey: Hex,
    sharedSecretHash: Hex,
  ): Promise<{ stealthAddress: Address; viewTag: Hex }> {
    const result = (await this.contract.read.deriveStealthAddress([
      recipient,
      ephemeralPubKey,
      sharedSecretHash,
    ])) as [Address, Hex];
    return { stealthAddress: result[0], viewTag: result[1] };
  }

  /**
   * Compute a dual-key stealth address and record it on-chain.
   * @param spendingPubKeyHash Hash of spending public key
   * @param viewingPubKeyHash  Hash of viewing public key
   * @param ephemeralPrivKeyHash Hash of ephemeral private key
   * @param chainId            Target chain ID
   * @returns Stealth hash and derived address
   */
  async computeDualKeyStealth(
    spendingPubKeyHash: Hex,
    viewingPubKeyHash: Hex,
    ephemeralPrivKeyHash: Hex,
    chainId: bigint,
  ): Promise<{ stealthHash: Hex; derivedAddress: Address }> {
    this.requireWallet();
    const result = (await this.contract.write!.computeDualKeyStealth([
      spendingPubKeyHash,
      viewingPubKeyHash,
      ephemeralPrivKeyHash,
      chainId,
    ])) as unknown as [Hex, Address];
    return { stealthHash: result[0], derivedAddress: result[1] };
  }

  /**
   * Derive a stealth key for a destination chain using a ZK derivation proof.
   * @param sourceStealthKey Source chain stealth key
   * @param destChainId      Destination chain ID
   * @param derivationProof  ZK proof of valid derivation
   * @returns Destination stealth key
   */
  async deriveCrossChainStealth(
    sourceStealthKey: Hex,
    destChainId: bigint,
    derivationProof: Hex,
  ): Promise<Hex> {
    this.requireWallet();
    return this.contract.write!.deriveCrossChainStealth([
      sourceStealthKey,
      destChainId,
      derivationProof,
    ]) as Promise<Hex>;
  }

  // ─── Announcements ──────────────────────────────────────────

  /**
   * Emit a stealth payment announcement (requires ANNOUNCER_ROLE).
   * @param schemeId        Stealth scheme identifier
   * @param stealthAddress  Derived stealth address
   * @param ephemeralPubKey Ephemeral public key for the payment
   * @param viewTag         View tag for efficient scanning
   * @param metadata        Optional encrypted metadata
   * @returns Transaction hash
   */
  async announce(
    schemeId: bigint,
    stealthAddress: Address,
    ephemeralPubKey: Hex,
    viewTag: Hex,
    metadata: Hex = "0x",
  ): Promise<Hex> {
    this.requireWallet();
    return this.contract.write!.announce([
      schemeId,
      stealthAddress,
      ephemeralPubKey,
      viewTag,
      metadata,
    ]) as Promise<Hex>;
  }

  /**
   * Self-service private announcement (costs >= 0.0001 ETH fee).
   * @param schemeId        Stealth scheme identifier
   * @param stealthAddress  Derived stealth address
   * @param ephemeralPubKey Ephemeral public key
   * @param viewTag         View tag
   * @param metadata        Optional encrypted metadata
   * @param value           ETH to send (must be >= 0.0001 ETH)
   * @returns Transaction hash
   */
  async announcePrivate(
    schemeId: bigint,
    stealthAddress: Address,
    ephemeralPubKey: Hex,
    viewTag: Hex,
    metadata: Hex = "0x",
    value: bigint = 100000000000000n, // 0.0001 ETH
  ): Promise<Hex> {
    this.requireWallet();
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    return (this.contract.write!.announcePrivate as any)(
      [schemeId, stealthAddress, ephemeralPubKey, viewTag, metadata],
      { value },
    ) as Promise<Hex>;
  }

  // ─── Scanning & Ownership ───────────────────────────────────

  /**
   * Get all stealth addresses associated with a view tag.
   * @param viewTag Single-byte view tag
   * @returns Array of stealth addresses
   */
  async getAnnouncementsByViewTag(viewTag: Hex): Promise<Address[]> {
    return (await this.contract.read.getAnnouncementsByViewTag([
      viewTag,
    ])) as Address[];
  }

  /**
   * Check if a stealth address is owned by the holder of given key hashes.
   * @param stealthAddress     The stealth address to check
   * @param viewingPrivKeyHash Hash of the viewing private key
   * @param spendingPubKeyHash Hash of the spending public key
   * @returns True if the address belongs to the key holder
   */
  async checkStealthOwnership(
    stealthAddress: Address,
    viewingPrivKeyHash: Hex,
    spendingPubKeyHash: Hex,
  ): Promise<boolean> {
    return (await this.contract.read.checkStealthOwnership([
      stealthAddress,
      viewingPrivKeyHash,
      spendingPubKeyHash,
    ])) as boolean;
  }

  /**
   * Batch-scan candidate stealth addresses to find those owned by the caller.
   * @param viewingPrivKeyHash Hash of the viewing private key
   * @param spendingPubKeyHash Hash of the spending public key
   * @param candidates         Array of candidate stealth addresses
   * @returns Array of addresses that belong to the key holder
   */
  async batchScan(
    viewingPrivKeyHash: Hex,
    spendingPubKeyHash: Hex,
    candidates: Address[],
  ): Promise<Address[]> {
    return (await this.contract.read.batchScan([
      viewingPrivKeyHash,
      spendingPubKeyHash,
      candidates,
    ])) as Address[];
  }

  // ─── Query ──────────────────────────────────────────────────

  /**
   * Get the stealth meta-address for an owner.
   * @param owner Address that registered a meta-address
   * @returns Meta-address record (or zero values if not registered)
   */
  async getMetaAddress(owner: Address): Promise<StealthMetaAddressRecord> {
    const raw = (await this.contract.read.getMetaAddress([owner])) as {
      spendingPubKey: Hex;
      viewingPubKey: Hex;
      curveType: number;
      status: number;
      registeredAt: bigint;
      schemeId: bigint;
    };
    return {
      spendingPubKey: raw.spendingPubKey,
      viewingPubKey: raw.viewingPubKey,
      curveType: raw.curveType as CurveType,
      status: raw.status as KeyStatus,
      registeredAt: raw.registeredAt,
      schemeId: raw.schemeId,
    };
  }

  /**
   * Get the announcement for a specific stealth address.
   * @param stealthAddress The stealth address to look up
   * @returns Announcement record
   */
  async getAnnouncement(stealthAddress: Address): Promise<AnnouncementRecord> {
    const raw = (await this.contract.read.getAnnouncement([
      stealthAddress,
    ])) as {
      schemeId: Hex;
      stealthAddress: Address;
      ephemeralPubKey: Hex;
      viewTag: Hex;
      metadata: Hex;
      timestamp: bigint;
      chainId: bigint;
    };
    return raw;
  }

  /**
   * Get a dual-key stealth record by hash.
   * @param stealthHash The stealth hash identifier
   * @returns Dual-key stealth record
   */
  async getDualKeyRecord(stealthHash: Hex): Promise<DualKeyStealthRecord> {
    const raw = (await this.contract.read.getDualKeyRecord([
      stealthHash,
    ])) as DualKeyStealthRecord;
    return raw;
  }

  /**
   * Get a cross-chain stealth binding.
   * @param sourceKey Source chain stealth key
   * @param destKey   Destination chain stealth key
   * @returns Cross-chain binding record
   */
  async getCrossChainBinding(
    sourceKey: Hex,
    destKey: Hex,
  ): Promise<CrossChainStealthBinding> {
    const raw = (await this.contract.read.getCrossChainBinding([
      sourceKey,
      destKey,
    ])) as CrossChainStealthBinding;
    return raw;
  }

  /**
   * Get the total number of registered meta-addresses.
   */
  async getRegisteredAddressCount(): Promise<bigint> {
    return (await this.contract.read.getRegisteredAddressCount([])) as bigint;
  }

  /**
   * Get total announcement count.
   */
  async getTotalAnnouncements(): Promise<bigint> {
    return (await this.contract.read.totalAnnouncements([])) as bigint;
  }

  /**
   * Get aggregate registry statistics.
   * @returns { registeredCount, announcementCount, crossChainDerivationCount }
   */
  async getStats(): Promise<RegistryStats> {
    const result = (await this.contract.read.getStats([])) as [
      bigint,
      bigint,
      bigint,
    ];
    return {
      registeredCount: result[0],
      announcementCount: result[1],
      crossChainDerivationCount: result[2],
    };
  }

  // ─── Admin ──────────────────────────────────────────────────

  /**
   * Set the ZK derivation verifier contract (DEFAULT_ADMIN_ROLE required).
   * @param verifier The IDerivationVerifier contract address
   * @returns Transaction hash
   */
  async setDerivationVerifier(verifier: Address): Promise<Hex> {
    this.requireWallet();
    return this.contract.write!.setDerivationVerifier([
      verifier,
    ]) as Promise<Hex>;
  }

  /**
   * Withdraw accumulated fees from private announcements (DEFAULT_ADMIN_ROLE required).
   * @param recipient Fee recipient
   * @param amount    Amount in wei
   * @returns Transaction hash
   */
  async withdrawFees(recipient: Address, amount: bigint): Promise<Hex> {
    this.requireWallet();
    return this.contract.write!.withdrawFees([
      recipient,
      amount,
    ]) as Promise<Hex>;
  }

  // ─── Helpers ────────────────────────────────────────────────

  private requireWallet(): void {
    if (!this.walletClient) {
      throw new Error(
        "StealthAddressRegistryClient: wallet client required for write operations",
      );
    }
  }
}
