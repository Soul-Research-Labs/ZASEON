/**
 * @title CrossChainProofHubV3 SDK Client
 * @description TypeScript client for cross-chain proof aggregation, challenge, and finalization
 *   via the CrossChainProofHubV3 contract.
 *
 * Supports submitting proofs, batching, challenging, resolving, and finalizing proofs
 * across chains with optimistic verification and relayer staking.
 */

import {
  PublicClient,
  WalletClient,
  getContract,
  Hex,
  decodeEventLog,
  Log,
} from "viem";
import { ViemContract, DecodedEventArgs } from "../types/contracts";

// ─── ABI ──────────────────────────────────────────────────────────────

const CROSS_CHAIN_PROOF_HUB_V3_ABI = [
  // ── Write: Relayer Stake ──
  {
    name: "depositStake",
    type: "function",
    stateMutability: "payable",
    inputs: [],
    outputs: [],
  },
  {
    name: "withdrawStake",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "amount", type: "uint256" }],
    outputs: [],
  },
  {
    name: "withdrawRewards",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "amount", type: "uint256" }],
    outputs: [],
  },
  // ── Write: Proof Submission ──
  {
    name: "submitProof",
    type: "function",
    stateMutability: "payable",
    inputs: [
      { name: "proof", type: "bytes" },
      { name: "publicInputs", type: "bytes" },
      { name: "commitment", type: "bytes32" },
      { name: "sourceChainId", type: "uint64" },
      { name: "destChainId", type: "uint64" },
    ],
    outputs: [{ name: "proofId", type: "bytes32" }],
  },
  {
    name: "submitProofInstant",
    type: "function",
    stateMutability: "payable",
    inputs: [
      { name: "proof", type: "bytes" },
      { name: "publicInputs", type: "bytes" },
      { name: "commitment", type: "bytes32" },
      { name: "sourceChainId", type: "uint64" },
      { name: "destChainId", type: "uint64" },
      { name: "proofType", type: "bytes32" },
    ],
    outputs: [{ name: "proofId", type: "bytes32" }],
  },
  {
    name: "submitBatch",
    type: "function",
    stateMutability: "payable",
    inputs: [
      {
        name: "_proofs",
        type: "tuple[]",
        components: [
          { name: "proofHash", type: "bytes32" },
          { name: "publicInputsHash", type: "bytes32" },
          { name: "commitment", type: "bytes32" },
          { name: "sourceChainId", type: "uint64" },
          { name: "destChainId", type: "uint64" },
        ],
      },
      { name: "merkleRoot", type: "bytes32" },
    ],
    outputs: [{ name: "batchId", type: "bytes32" }],
  },
  // ── Write: Challenge ──
  {
    name: "challengeProof",
    type: "function",
    stateMutability: "payable",
    inputs: [
      { name: "proofId", type: "bytes32" },
      { name: "reason", type: "string" },
    ],
    outputs: [],
  },
  {
    name: "resolveChallenge",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "proofId", type: "bytes32" },
      { name: "proof", type: "bytes" },
      { name: "publicInputs", type: "bytes" },
      { name: "proofType", type: "bytes32" },
    ],
    outputs: [],
  },
  {
    name: "expireChallenge",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "proofId", type: "bytes32" }],
    outputs: [],
  },
  // ── Write: Finalization ──
  {
    name: "finalizeProof",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "proofId", type: "bytes32" }],
    outputs: [],
  },
  // ── Write: Admin ──
  {
    name: "setVerifier",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "proofType", type: "bytes32" },
      { name: "_verifier", type: "address" },
    ],
    outputs: [],
  },
  {
    name: "addSupportedChain",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "chainId", type: "uint256" }],
    outputs: [],
  },
  {
    name: "removeSupportedChain",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "chainId", type: "uint256" }],
    outputs: [],
  },
  {
    name: "setTrustedRemote",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "chainId", type: "uint256" },
      { name: "remote", type: "address" },
    ],
    outputs: [],
  },
  {
    name: "setChallengePeriod",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "_period", type: "uint256" }],
    outputs: [],
  },
  {
    name: "setMinStakes",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "_relayerStake", type: "uint256" },
      { name: "_challengerStake", type: "uint256" },
    ],
    outputs: [],
  },
  {
    name: "setProofSubmissionFee",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "_fee", type: "uint256" }],
    outputs: [],
  },
  {
    name: "setRateLimits",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "_maxProofsPerHour", type: "uint256" },
      { name: "_maxValuePerHour", type: "uint256" },
    ],
    outputs: [],
  },
  {
    name: "pause",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [],
    outputs: [],
  },
  {
    name: "unpause",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [],
    outputs: [],
  },
  // ── Read ──
  {
    name: "getProof",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "proofId", type: "bytes32" }],
    outputs: [
      {
        name: "",
        type: "tuple",
        components: [
          { name: "proofHash", type: "bytes32" },
          { name: "publicInputsHash", type: "bytes32" },
          { name: "commitment", type: "bytes32" },
          { name: "sourceChainId", type: "uint64" },
          { name: "destChainId", type: "uint64" },
          { name: "submittedAt", type: "uint64" },
          { name: "challengeDeadline", type: "uint64" },
          { name: "relayer", type: "address" },
          { name: "status", type: "uint8" },
          { name: "stake", type: "uint256" },
        ],
      },
    ],
  },
  {
    name: "getBatch",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "batchId", type: "bytes32" }],
    outputs: [
      {
        name: "",
        type: "tuple",
        components: [
          { name: "batchId", type: "bytes32" },
          { name: "merkleRoot", type: "bytes32" },
          { name: "proofCount", type: "uint256" },
          { name: "submittedAt", type: "uint64" },
          { name: "challengeDeadline", type: "uint64" },
          { name: "relayer", type: "address" },
          { name: "status", type: "uint8" },
          { name: "totalStake", type: "uint256" },
        ],
      },
    ],
  },
  {
    name: "getChallenge",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "proofId", type: "bytes32" }],
    outputs: [
      {
        name: "",
        type: "tuple",
        components: [
          { name: "proofId", type: "bytes32" },
          { name: "challenger", type: "address" },
          { name: "stake", type: "uint256" },
          { name: "createdAt", type: "uint64" },
          { name: "deadline", type: "uint64" },
          { name: "resolved", type: "bool" },
          { name: "challengerWon", type: "bool" },
          { name: "reason", type: "string" },
        ],
      },
    ],
  },
  {
    name: "isProofFinalized",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "proofId", type: "bytes32" }],
    outputs: [{ name: "", type: "bool" }],
  },
  {
    name: "getRelayerStats",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "relayer", type: "address" }],
    outputs: [
      { name: "stake", type: "uint256" },
      { name: "successCount", type: "uint256" },
      { name: "slashCount", type: "uint256" },
    ],
  },
  {
    name: "challengePeriod",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "uint256" }],
  },
  {
    name: "minRelayerStake",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "uint256" }],
  },
  {
    name: "minChallengerStake",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "uint256" }],
  },
  {
    name: "totalProofs",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "uint256" }],
  },
  {
    name: "totalBatches",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "uint256" }],
  },
  {
    name: "proofSubmissionFee",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "uint256" }],
  },
  {
    name: "relayerStakes",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "relayer", type: "address" }],
    outputs: [{ name: "", type: "uint256" }],
  },
  {
    name: "claimableRewards",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "relayer", type: "address" }],
    outputs: [{ name: "", type: "uint256" }],
  },
  {
    name: "supportedChains",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "chainId", type: "uint256" }],
    outputs: [{ name: "", type: "bool" }],
  },
  {
    name: "paused",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "bool" }],
  },
  // ── Events ──
  {
    name: "ProofSubmitted",
    type: "event",
    inputs: [
      { name: "proofId", type: "bytes32", indexed: true },
      { name: "commitment", type: "bytes32", indexed: true },
      { name: "sourceChainId", type: "uint64", indexed: false },
      { name: "destChainId", type: "uint64", indexed: false },
      { name: "relayer", type: "address", indexed: true },
    ],
  },
  {
    name: "BatchSubmitted",
    type: "event",
    inputs: [
      { name: "batchId", type: "bytes32", indexed: true },
      { name: "merkleRoot", type: "bytes32", indexed: true },
      { name: "proofCount", type: "uint256", indexed: true },
      { name: "relayer", type: "address", indexed: false },
    ],
  },
  {
    name: "ProofFinalized",
    type: "event",
    inputs: [{ name: "proofId", type: "bytes32", indexed: true }],
  },
  {
    name: "ProofRejected",
    type: "event",
    inputs: [
      { name: "proofId", type: "bytes32", indexed: true },
      { name: "reason", type: "string", indexed: false },
    ],
  },
  {
    name: "ChallengeCreated",
    type: "event",
    inputs: [
      { name: "proofId", type: "bytes32", indexed: true },
      { name: "challenger", type: "address", indexed: true },
      { name: "reason", type: "string", indexed: false },
    ],
  },
  {
    name: "ChallengeResolved",
    type: "event",
    inputs: [
      { name: "proofId", type: "bytes32", indexed: true },
      { name: "challengerWon", type: "bool", indexed: false },
      { name: "winner", type: "address", indexed: true },
      { name: "reward", type: "uint256", indexed: false },
    ],
  },
  {
    name: "RelayerStakeDeposited",
    type: "event",
    inputs: [
      { name: "relayer", type: "address", indexed: true },
      { name: "amount", type: "uint256", indexed: true },
    ],
  },
  {
    name: "RelayerSlashed",
    type: "event",
    inputs: [
      { name: "relayer", type: "address", indexed: true },
      { name: "amount", type: "uint256", indexed: true },
    ],
  },
] as const;

// ─── Types ────────────────────────────────────────────────────────────

/** Proof status matching on-chain ProofStatus enum */
export enum ProofStatus {
  Pending = 0,
  Verified = 1,
  Challenged = 2,
  Rejected = 3,
  Finalized = 4,
}

/** On-chain ProofSubmission data */
export interface ProofSubmission {
  proofHash: Hex;
  publicInputsHash: Hex;
  commitment: Hex;
  sourceChainId: bigint;
  destChainId: bigint;
  submittedAt: bigint;
  challengeDeadline: bigint;
  relayer: Hex;
  status: ProofStatus;
  stake: bigint;
}

/** On-chain BatchSubmission data */
export interface BatchSubmission {
  batchId: Hex;
  merkleRoot: Hex;
  proofCount: bigint;
  submittedAt: bigint;
  challengeDeadline: bigint;
  relayer: Hex;
  status: ProofStatus;
  totalStake: bigint;
}

/** On-chain Challenge data */
export interface ChallengeInfo {
  proofId: Hex;
  challenger: Hex;
  stake: bigint;
  createdAt: bigint;
  deadline: bigint;
  resolved: boolean;
  challengerWon: boolean;
  reason: string;
}

/** Input for batch proof submission */
export interface BatchProofInput {
  proofHash: Hex;
  publicInputsHash: Hex;
  commitment: Hex;
  sourceChainId: bigint;
  destChainId: bigint;
}

/** Relayer statistics */
export interface RelayerStats {
  stake: bigint;
  successCount: bigint;
  slashCount: bigint;
}

/** Result of submitting a proof */
export interface SubmitProofResult {
  txHash: Hex;
  proofId: Hex;
}

/** Result of submitting a batch */
export interface SubmitBatchResult {
  txHash: Hex;
  batchId: Hex;
}

/** Hub configuration snapshot */
export interface ProofHubConfig {
  challengePeriod: bigint;
  minRelayerStake: bigint;
  minChallengerStake: bigint;
  proofSubmissionFee: bigint;
  totalProofs: bigint;
  totalBatches: bigint;
  paused: boolean;
}

// ─── Client ───────────────────────────────────────────────────────────

/**
 * SDK client for the CrossChainProofHubV3 contract.
 *
 * Provides a typed interface for cross-chain proof aggregation including
 * proof submission, batching, challenging, and finalization with optimistic
 * verification and relayer staking.
 *
 * @example
 * ```ts
 * const hub = new CrossChainProofHubV3Client(address, publicClient, walletClient);
 *
 * // Submit a proof
 * const { proofId } = await hub.submitProof(proofBytes, inputsBytes, commitment, 42161n, 10n);
 *
 * // Wait for challenge period, then finalize
 * await hub.finalizeProof(proofId);
 * ```
 */
export class CrossChainProofHubV3Client {
  public readonly contract: ViemContract;
  private readonly publicClient: PublicClient;
  private readonly walletClient?: WalletClient;

  constructor(
    contractAddress: Hex,
    publicClient: PublicClient,
    walletClient?: WalletClient,
  ) {
    this.publicClient = publicClient;
    this.walletClient = walletClient;
    this.contract = getContract({
      address: contractAddress,
      abi: CROSS_CHAIN_PROOF_HUB_V3_ABI,
      client: { public: publicClient, wallet: walletClient },
    }) as unknown as ViemContract;
  }

  // ── Write: Relayer Stake ──────────────────────────────────────────

  /**
   * Deposit ETH as relayer stake.
   * @param amount - Amount of ETH to stake (in wei)
   * @returns Transaction hash
   */
  async depositStake(amount: bigint): Promise<Hex> {
    if (!this.walletClient) throw new Error("Wallet client required for write operations");
    const hash = await this.contract.write.depositStake([], { value: amount });
    await this.publicClient.waitForTransactionReceipt({ hash });
    return hash;
  }

  /**
   * Withdraw relayer stake.
   * @param amount - Amount to withdraw (in wei)
   * @returns Transaction hash
   */
  async withdrawStake(amount: bigint): Promise<Hex> {
    if (!this.walletClient) throw new Error("Wallet client required for write operations");
    const hash = await this.contract.write.withdrawStake([amount]);
    await this.publicClient.waitForTransactionReceipt({ hash });
    return hash;
  }

  /**
   * Withdraw accumulated relayer rewards.
   * @param amount - Amount to withdraw (in wei)
   * @returns Transaction hash
   */
  async withdrawRewards(amount: bigint): Promise<Hex> {
    if (!this.walletClient) throw new Error("Wallet client required for write operations");
    const hash = await this.contract.write.withdrawRewards([amount]);
    await this.publicClient.waitForTransactionReceipt({ hash });
    return hash;
  }

  // ── Write: Proof Submission ───────────────────────────────────────

  /**
   * Submit a single proof for optimistic verification.
   *
   * The proof enters a challenge period before finalization.
   * Requires relayer stake and submission fee.
   *
   * @param proof - Encoded proof data
   * @param publicInputs - Encoded public inputs
   * @param commitment - Privacy commitment hash
   * @param sourceChainId - Origin chain ID
   * @param destChainId - Destination chain ID
   * @param fee - Submission fee in wei (optional, reads from contract if 0)
   * @returns Transaction hash and proof ID
   */
  async submitProof(
    proof: Hex,
    publicInputs: Hex,
    commitment: Hex,
    sourceChainId: bigint,
    destChainId: bigint,
    fee?: bigint,
  ): Promise<SubmitProofResult> {
    if (!this.walletClient) throw new Error("Wallet client required for write operations");
    const value = fee ?? (await this.getProofSubmissionFee());
    const hash = await this.contract.write.submitProof(
      [proof, publicInputs, commitment, sourceChainId, destChainId],
      { value },
    );
    const receipt = await this.publicClient.waitForTransactionReceipt({ hash });

    let proofId: Hex = "0x" as Hex;
    for (const log of receipt.logs) {
      try {
        const decoded = decodeEventLog({
          abi: CROSS_CHAIN_PROOF_HUB_V3_ABI,
          data: log.data,
          topics: log.topics,
        });
        if (decoded.eventName === "ProofSubmitted") {
          const args = decoded.args as DecodedEventArgs;
          proofId = args["proofId"] as Hex;
          break;
        }
      } catch {
        // Not our event
      }
    }

    return { txHash: hash, proofId };
  }

  /**
   * Submit a proof with instant on-chain verification (bypasses challenge period).
   *
   * @param proof - Encoded proof data
   * @param publicInputs - Encoded public inputs
   * @param commitment - Privacy commitment hash
   * @param sourceChainId - Origin chain ID
   * @param destChainId - Destination chain ID
   * @param proofType - Proof type identifier (e.g. keccak256("groth16"))
   * @param fee - Submission fee in wei
   * @returns Transaction hash and proof ID
   */
  async submitProofInstant(
    proof: Hex,
    publicInputs: Hex,
    commitment: Hex,
    sourceChainId: bigint,
    destChainId: bigint,
    proofType: Hex,
    fee?: bigint,
  ): Promise<SubmitProofResult> {
    if (!this.walletClient) throw new Error("Wallet client required for write operations");
    const value = fee ?? (await this.getProofSubmissionFee());
    const hash = await this.contract.write.submitProofInstant(
      [proof, publicInputs, commitment, sourceChainId, destChainId, proofType],
      { value },
    );
    const receipt = await this.publicClient.waitForTransactionReceipt({ hash });

    let proofId: Hex = "0x" as Hex;
    for (const log of receipt.logs) {
      try {
        const decoded = decodeEventLog({
          abi: CROSS_CHAIN_PROOF_HUB_V3_ABI,
          data: log.data,
          topics: log.topics,
        });
        if (decoded.eventName === "ProofSubmitted") {
          const args = decoded.args as DecodedEventArgs;
          proofId = args["proofId"] as Hex;
          break;
        }
      } catch {
        // Not our event
      }
    }

    return { txHash: hash, proofId };
  }

  /**
   * Submit a batch of proofs with a Merkle root.
   *
   * More gas-efficient than individual submissions for multiple proofs.
   *
   * @param proofs - Array of batch proof inputs
   * @param merkleRoot - Merkle root of the proof batch
   * @param fee - Total fee for the batch (per-proof fee × count)
   * @returns Transaction hash and batch ID
   */
  async submitBatch(
    proofs: BatchProofInput[],
    merkleRoot: Hex,
    fee?: bigint,
  ): Promise<SubmitBatchResult> {
    if (!this.walletClient) throw new Error("Wallet client required for write operations");
    const perProofFee = await this.getProofSubmissionFee();
    const value = fee ?? perProofFee * BigInt(proofs.length);

    const inputs = proofs.map((p) => ({
      proofHash: p.proofHash,
      publicInputsHash: p.publicInputsHash,
      commitment: p.commitment,
      sourceChainId: p.sourceChainId,
      destChainId: p.destChainId,
    }));

    const hash = await this.contract.write.submitBatch(
      [inputs, merkleRoot],
      { value },
    );
    const receipt = await this.publicClient.waitForTransactionReceipt({ hash });

    let batchId: Hex = "0x" as Hex;
    for (const log of receipt.logs) {
      try {
        const decoded = decodeEventLog({
          abi: CROSS_CHAIN_PROOF_HUB_V3_ABI,
          data: log.data,
          topics: log.topics,
        });
        if (decoded.eventName === "BatchSubmitted") {
          const args = decoded.args as DecodedEventArgs;
          batchId = args["batchId"] as Hex;
          break;
        }
      } catch {
        // Not our event
      }
    }

    return { txHash: hash, batchId };
  }

  // ── Write: Challenge ──────────────────────────────────────────────

  /**
   * Challenge a proof during its challenge period.
   *
   * Requires minimum challenger stake as msg.value.
   *
   * @param proofId - ID of the proof to challenge
   * @param reason - Human-readable challenge reason
   * @param stake - Challenger stake amount in wei
   * @returns Transaction hash
   */
  async challengeProof(
    proofId: Hex,
    reason: string,
    stake: bigint,
  ): Promise<Hex> {
    if (!this.walletClient) throw new Error("Wallet client required for write operations");
    const hash = await this.contract.write.challengeProof(
      [proofId, reason],
      { value: stake },
    );
    await this.publicClient.waitForTransactionReceipt({ hash });
    return hash;
  }

  /**
   * Resolve a challenge by re-verifying the proof on-chain.
   *
   * @param proofId - ID of the challenged proof
   * @param proof - Original proof data
   * @param publicInputs - Original public inputs
   * @param proofType - Proof type identifier
   * @returns Transaction hash
   */
  async resolveChallenge(
    proofId: Hex,
    proof: Hex,
    publicInputs: Hex,
    proofType: Hex,
  ): Promise<Hex> {
    if (!this.walletClient) throw new Error("Wallet client required for write operations");
    const hash = await this.contract.write.resolveChallenge([
      proofId,
      proof,
      publicInputs,
      proofType,
    ]);
    await this.publicClient.waitForTransactionReceipt({ hash });
    return hash;
  }

  /**
   * Expire an unresolved challenge after its deadline.
   *
   * @param proofId - ID of the challenged proof
   * @returns Transaction hash
   */
  async expireChallenge(proofId: Hex): Promise<Hex> {
    if (!this.walletClient) throw new Error("Wallet client required for write operations");
    const hash = await this.contract.write.expireChallenge([proofId]);
    await this.publicClient.waitForTransactionReceipt({ hash });
    return hash;
  }

  // ── Write: Finalization ───────────────────────────────────────────

  /**
   * Finalize a proof after the challenge period has passed.
   *
   * @param proofId - ID of the proof to finalize
   * @returns Transaction hash
   */
  async finalizeProof(proofId: Hex): Promise<Hex> {
    if (!this.walletClient) throw new Error("Wallet client required for write operations");
    const hash = await this.contract.write.finalizeProof([proofId]);
    await this.publicClient.waitForTransactionReceipt({ hash });
    return hash;
  }

  // ── Write: Admin ──────────────────────────────────────────────────

  /** Set a verifier contract for a given proof type. */
  async setVerifier(proofType: Hex, verifier: Hex): Promise<Hex> {
    if (!this.walletClient) throw new Error("Wallet client required for write operations");
    const hash = await this.contract.write.setVerifier([proofType, verifier]);
    await this.publicClient.waitForTransactionReceipt({ hash });
    return hash;
  }

  /** Add a chain ID to the supported chains list. */
  async addSupportedChain(chainId: bigint): Promise<Hex> {
    if (!this.walletClient) throw new Error("Wallet client required for write operations");
    const hash = await this.contract.write.addSupportedChain([chainId]);
    await this.publicClient.waitForTransactionReceipt({ hash });
    return hash;
  }

  /** Remove a chain ID from the supported chains list. */
  async removeSupportedChain(chainId: bigint): Promise<Hex> {
    if (!this.walletClient) throw new Error("Wallet client required for write operations");
    const hash = await this.contract.write.removeSupportedChain([chainId]);
    await this.publicClient.waitForTransactionReceipt({ hash });
    return hash;
  }

  /** Set a trusted remote address for a chain. */
  async setTrustedRemote(chainId: bigint, remote: Hex): Promise<Hex> {
    if (!this.walletClient) throw new Error("Wallet client required for write operations");
    const hash = await this.contract.write.setTrustedRemote([chainId, remote]);
    await this.publicClient.waitForTransactionReceipt({ hash });
    return hash;
  }

  /** Update the challenge period duration. */
  async setChallengePeriod(period: bigint): Promise<Hex> {
    if (!this.walletClient) throw new Error("Wallet client required for write operations");
    const hash = await this.contract.write.setChallengePeriod([period]);
    await this.publicClient.waitForTransactionReceipt({ hash });
    return hash;
  }

  /** Update minimum relayer and challenger stake requirements. */
  async setMinStakes(
    relayerStake: bigint,
    challengerStake: bigint,
  ): Promise<Hex> {
    if (!this.walletClient) throw new Error("Wallet client required for write operations");
    const hash = await this.contract.write.setMinStakes([
      relayerStake,
      challengerStake,
    ]);
    await this.publicClient.waitForTransactionReceipt({ hash });
    return hash;
  }

  /** Update the per-proof submission fee. */
  async setProofSubmissionFee(fee: bigint): Promise<Hex> {
    if (!this.walletClient) throw new Error("Wallet client required for write operations");
    const hash = await this.contract.write.setProofSubmissionFee([fee]);
    await this.publicClient.waitForTransactionReceipt({ hash });
    return hash;
  }

  /** Update rate limits for proof submission. */
  async setRateLimits(
    maxProofsPerHour: bigint,
    maxValuePerHour: bigint,
  ): Promise<Hex> {
    if (!this.walletClient) throw new Error("Wallet client required for write operations");
    const hash = await this.contract.write.setRateLimits([
      maxProofsPerHour,
      maxValuePerHour,
    ]);
    await this.publicClient.waitForTransactionReceipt({ hash });
    return hash;
  }

  /** Emergency pause the hub. */
  async pause(): Promise<Hex> {
    if (!this.walletClient) throw new Error("Wallet client required for write operations");
    const hash = await this.contract.write.pause([]);
    await this.publicClient.waitForTransactionReceipt({ hash });
    return hash;
  }

  /** Unpause the hub. */
  async unpause(): Promise<Hex> {
    if (!this.walletClient) throw new Error("Wallet client required for write operations");
    const hash = await this.contract.write.unpause([]);
    await this.publicClient.waitForTransactionReceipt({ hash });
    return hash;
  }

  // ── Read Methods ──────────────────────────────────────────────────

  /** Get full proof submission data by ID. */
  async getProof(proofId: Hex): Promise<ProofSubmission> {
    const raw = await this.contract.read.getProof([proofId]);
    const r = raw as Record<string, unknown>;
    return {
      proofHash: r.proofHash as Hex,
      publicInputsHash: r.publicInputsHash as Hex,
      commitment: r.commitment as Hex,
      sourceChainId: BigInt(r.sourceChainId as number),
      destChainId: BigInt(r.destChainId as number),
      submittedAt: BigInt(r.submittedAt as number),
      challengeDeadline: BigInt(r.challengeDeadline as number),
      relayer: r.relayer as Hex,
      status: Number(r.status) as ProofStatus,
      stake: BigInt(r.stake as bigint),
    };
  }

  /** Get batch submission data by ID. */
  async getBatch(batchId: Hex): Promise<BatchSubmission> {
    const raw = await this.contract.read.getBatch([batchId]);
    const r = raw as Record<string, unknown>;
    return {
      batchId: r.batchId as Hex,
      merkleRoot: r.merkleRoot as Hex,
      proofCount: BigInt(r.proofCount as bigint),
      submittedAt: BigInt(r.submittedAt as number),
      challengeDeadline: BigInt(r.challengeDeadline as number),
      relayer: r.relayer as Hex,
      status: Number(r.status) as ProofStatus,
      totalStake: BigInt(r.totalStake as bigint),
    };
  }

  /** Get challenge data for a proof. */
  async getChallenge(proofId: Hex): Promise<ChallengeInfo> {
    const raw = await this.contract.read.getChallenge([proofId]);
    const r = raw as Record<string, unknown>;
    return {
      proofId: r.proofId as Hex,
      challenger: r.challenger as Hex,
      stake: BigInt(r.stake as bigint),
      createdAt: BigInt(r.createdAt as number),
      deadline: BigInt(r.deadline as number),
      resolved: r.resolved as boolean,
      challengerWon: r.challengerWon as boolean,
      reason: r.reason as string,
    };
  }

  /** Check if a proof has been finalized. */
  async isProofFinalized(proofId: Hex): Promise<boolean> {
    return (await this.contract.read.isProofFinalized([proofId])) as boolean;
  }

  /** Get relayer staking and performance stats. */
  async getRelayerStats(relayer: Hex): Promise<RelayerStats> {
    const [stake, successCount, slashCount] = (await this.contract.read
      .getRelayerStats([relayer])) as [bigint, bigint, bigint];
    return { stake, successCount, slashCount };
  }

  /** Get the current challenge period duration (seconds). */
  async getChallengePeriod(): Promise<bigint> {
    return (await this.contract.read.challengePeriod([])) as bigint;
  }

  /** Get the minimum relayer stake requirement. */
  async getMinRelayerStake(): Promise<bigint> {
    return (await this.contract.read.minRelayerStake([])) as bigint;
  }

  /** Get the minimum challenger stake requirement. */
  async getMinChallengerStake(): Promise<bigint> {
    return (await this.contract.read.minChallengerStake([])) as bigint;
  }

  /** Get total number of proofs submitted. */
  async getTotalProofs(): Promise<bigint> {
    return (await this.contract.read.totalProofs([])) as bigint;
  }

  /** Get total number of batches submitted. */
  async getTotalBatches(): Promise<bigint> {
    return (await this.contract.read.totalBatches([])) as bigint;
  }

  /** Get the current proof submission fee. */
  async getProofSubmissionFee(): Promise<bigint> {
    return (await this.contract.read.proofSubmissionFee([])) as bigint;
  }

  /** Get a relayer's current stake. */
  async getRelayerStake(relayer: Hex): Promise<bigint> {
    return (await this.contract.read.relayerStakes([relayer])) as bigint;
  }

  /** Get a relayer's claimable rewards. */
  async getClaimableRewards(relayer: Hex): Promise<bigint> {
    return (await this.contract.read.claimableRewards([relayer])) as bigint;
  }

  /** Check if a chain is supported. */
  async isChainSupported(chainId: bigint): Promise<boolean> {
    return (await this.contract.read.supportedChains([chainId])) as boolean;
  }

  /** Check if the hub is paused. */
  async isPaused(): Promise<boolean> {
    return (await this.contract.read.paused([])) as boolean;
  }

  /** Get a snapshot of hub configuration. */
  async getConfig(): Promise<ProofHubConfig> {
    const [
      challengePeriod,
      minRelayerStake,
      minChallengerStake,
      proofSubmissionFee,
      totalProofs,
      totalBatches,
      paused,
    ] = await Promise.all([
      this.getChallengePeriod(),
      this.getMinRelayerStake(),
      this.getMinChallengerStake(),
      this.getProofSubmissionFee(),
      this.getTotalProofs(),
      this.getTotalBatches(),
      this.isPaused(),
    ]);
    return {
      challengePeriod,
      minRelayerStake,
      minChallengerStake,
      proofSubmissionFee,
      totalProofs,
      totalBatches,
      paused,
    };
  }

  // ── Event Watchers ────────────────────────────────────────────────

  /**
   * Watch for new proof submissions.
   * @returns An unwatch function to stop listening
   */
  watchProofSubmitted(
    callback: (proofId: Hex, commitment: Hex, relayer: Hex) => void,
  ) {
    return this.publicClient.watchContractEvent({
      address: this.contract.address as Hex,
      abi: CROSS_CHAIN_PROOF_HUB_V3_ABI,
      eventName: "ProofSubmitted",
      onLogs: (logs: Log[]) => {
        for (const log of logs) {
          try {
            const decoded = decodeEventLog({
              abi: CROSS_CHAIN_PROOF_HUB_V3_ABI,
              data: log.data,
              topics: log.topics,
            });
            if (decoded.eventName === "ProofSubmitted") {
              const args = decoded.args as DecodedEventArgs;
              callback(
                args["proofId"] as Hex,
                args["commitment"] as Hex,
                args["relayer"] as Hex,
              );
            }
          } catch {
            // Skip non-matching logs
          }
        }
      },
    });
  }

  /**
   * Watch for proof finalization events.
   * @returns An unwatch function to stop listening
   */
  watchProofFinalized(callback: (proofId: Hex) => void) {
    return this.publicClient.watchContractEvent({
      address: this.contract.address as Hex,
      abi: CROSS_CHAIN_PROOF_HUB_V3_ABI,
      eventName: "ProofFinalized",
      onLogs: (logs: Log[]) => {
        for (const log of logs) {
          try {
            const decoded = decodeEventLog({
              abi: CROSS_CHAIN_PROOF_HUB_V3_ABI,
              data: log.data,
              topics: log.topics,
            });
            if (decoded.eventName === "ProofFinalized") {
              const args = decoded.args as DecodedEventArgs;
              callback(args["proofId"] as Hex);
            }
          } catch {
            // Skip
          }
        }
      },
    });
  }

  /**
   * Watch for challenge events.
   * @returns An unwatch function to stop listening
   */
  watchChallengeCreated(
    callback: (proofId: Hex, challenger: Hex, reason: string) => void,
  ) {
    return this.publicClient.watchContractEvent({
      address: this.contract.address as Hex,
      abi: CROSS_CHAIN_PROOF_HUB_V3_ABI,
      eventName: "ChallengeCreated",
      onLogs: (logs: Log[]) => {
        for (const log of logs) {
          try {
            const decoded = decodeEventLog({
              abi: CROSS_CHAIN_PROOF_HUB_V3_ABI,
              data: log.data,
              topics: log.topics,
            });
            if (decoded.eventName === "ChallengeCreated") {
              const args = decoded.args as DecodedEventArgs;
              callback(
                args["proofId"] as Hex,
                args["challenger"] as Hex,
                args["reason"] as string,
              );
            }
          } catch {
            // Skip
          }
        }
      },
    });
  }

  /**
   * Watch for relayer slashing events (security monitoring).
   * @returns An unwatch function to stop listening
   */
  watchRelayerSlashed(
    callback: (relayer: Hex, amount: bigint) => void,
  ) {
    return this.publicClient.watchContractEvent({
      address: this.contract.address as Hex,
      abi: CROSS_CHAIN_PROOF_HUB_V3_ABI,
      eventName: "RelayerSlashed",
      onLogs: (logs: Log[]) => {
        for (const log of logs) {
          try {
            const decoded = decodeEventLog({
              abi: CROSS_CHAIN_PROOF_HUB_V3_ABI,
              data: log.data,
              topics: log.topics,
            });
            if (decoded.eventName === "RelayerSlashed") {
              const args = decoded.args as DecodedEventArgs;
              callback(
                args["relayer"] as Hex,
                args["amount"] as bigint,
              );
            }
          } catch {
            // Skip
          }
        }
      },
    });
  }

}
