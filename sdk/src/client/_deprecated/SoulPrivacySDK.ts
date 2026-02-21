/**
 * Soul Privacy SDK — Unified Client
 *
 * @deprecated This class is orphaned and duplicates functionality already provided
 * by the individually-exported `PrivacyRouterClient`, `ShieldedPoolClient`, and
 * `RelayerFeeMarketClient`. Use those clients instead, or use `SoulProtocolClient`
 * as the single main entry point. This file will be removed in v2.0.
 *
 * Combines all privacy middleware clients (ShieldedPool, PrivacyRouter,
 * RelayerFeeMarket) into a single developer-facing SDK.
 *
 * @example
 * ```ts
 * import { SoulPrivacySDK } from "./SoulPrivacySDK";
 *
 * const sdk = new SoulPrivacySDK({
 *   publicClient,
 *   walletClient,
 *   addresses: {
 *     shieldedPool: "0x...",
 *     privacyRouter: "0x...",
 *     feeMarket: "0x...",
 *   },
 * });
 *
 * // Generate deposit commitment
 * const note = sdk.generateDepositNote(parseEther("1"));
 *
 * // Deposit via router
 * const txHash = await sdk.depositETH(note.commitment, parseEther("1"));
 *
 * // Query pool stats
 * const stats = await sdk.getPoolStats();
 * ```
 */

import {
    type PublicClient,
    type WalletClient,
    type Hex,
    type Address,
    type Hash,
    keccak256,
    encodePacked,
    toBytes,
    zeroAddress,
    pad,
} from "viem";

/*//////////////////////////////////////////////////////////////
                          TYPES
//////////////////////////////////////////////////////////////*/

export interface SoulPrivacySDKConfig {
    publicClient: PublicClient;
    walletClient?: WalletClient;
    addresses: {
        shieldedPool?: Address;
        privacyRouter?: Address;
        feeMarket?: Address;
        crossChainHub?: Address;
        commitmentRelay?: Address;
    };
}

export interface DepositNote {
    commitment: Hex;
    secret: Hex;
    nullifierPreimage: Hex;
    amount: bigint;
    assetId: Hex;
    leafIndex?: number;
}

export interface WithdrawInput {
    note: DepositNote;
    merkleRoot: Hex;
    recipient: Address;
    relayer?: Address;
    relayerFee?: bigint;
}

export interface PoolStats {
    totalDeposits: bigint;
    totalWithdrawals: bigint;
    crossChainDeposits: bigint;
    treeSize: bigint;
    currentRoot: Hex;
}

export interface FeeEstimate {
    baseFee: bigint;
    priorityFee: bigint;
    totalFee: bigint;
}

/*//////////////////////////////////////////////////////////////
                        ABI FRAGMENTS
//////////////////////////////////////////////////////////////*/

const POOL_ABI = [
    {
        name: "depositETH",
        type: "function",
        stateMutability: "payable",
        inputs: [{ name: "commitment", type: "bytes32" }],
        outputs: [],
    },
    {
        name: "depositERC20",
        type: "function",
        stateMutability: "nonpayable",
        inputs: [
            { name: "assetId", type: "bytes32" },
            { name: "amount", type: "uint256" },
            { name: "commitment", type: "bytes32" },
        ],
        outputs: [],
    },
    {
        name: "withdraw",
        type: "function",
        stateMutability: "nonpayable",
        inputs: [
            {
                name: "wp",
                type: "tuple",
                components: [
                    { name: "proof", type: "bytes" },
                    { name: "merkleRoot", type: "bytes32" },
                    { name: "nullifier", type: "bytes32" },
                    { name: "recipient", type: "address" },
                    { name: "relayerAddress", type: "address" },
                    { name: "amount", type: "uint256" },
                    { name: "relayerFee", type: "uint256" },
                    { name: "assetId", type: "bytes32" },
                    { name: "destChainId", type: "bytes32" },
                ],
            },
        ],
        outputs: [],
    },
    {
        name: "getPoolStats",
        type: "function",
        stateMutability: "view",
        inputs: [],
        outputs: [
            { name: "deposits", type: "uint256" },
            { name: "withdrawalsCount", type: "uint256" },
            { name: "crossChainDeposits", type: "uint256" },
            { name: "treeSize", type: "uint256" },
            { name: "root", type: "bytes32" },
        ],
    },
    {
        name: "currentRoot",
        type: "function",
        stateMutability: "view",
        inputs: [],
        outputs: [{ name: "", type: "bytes32" }],
    },
    {
        name: "isKnownRoot",
        type: "function",
        stateMutability: "view",
        inputs: [{ name: "root", type: "bytes32" }],
        outputs: [{ name: "", type: "bool" }],
    },
    {
        name: "isSpent",
        type: "function",
        stateMutability: "view",
        inputs: [{ name: "nullifier", type: "bytes32" }],
        outputs: [{ name: "", type: "bool" }],
    },
    {
        name: "nextLeafIndex",
        type: "function",
        stateMutability: "view",
        inputs: [],
        outputs: [{ name: "", type: "uint256" }],
    },
] as const;

const ROUTER_ABI = [
    {
        name: "depositETH",
        type: "function",
        stateMutability: "payable",
        inputs: [{ name: "commitment", type: "bytes32" }],
        outputs: [{ name: "operationId", type: "bytes32" }],
    },
    {
        name: "depositERC20",
        type: "function",
        stateMutability: "nonpayable",
        inputs: [
            { name: "assetId", type: "bytes32" },
            { name: "amount", type: "uint256" },
            { name: "commitment", type: "bytes32" },
        ],
        outputs: [{ name: "operationId", type: "bytes32" }],
    },
    {
        name: "operationNonce",
        type: "function",
        stateMutability: "view",
        inputs: [],
        outputs: [{ name: "", type: "uint256" }],
    },
] as const;

/*//////////////////////////////////////////////////////////////
                        SDK CLASS
//////////////////////////////////////////////////////////////*/

export class SoulPrivacySDK {
    public readonly publicClient: PublicClient;
    public readonly walletClient?: WalletClient;
    public readonly addresses: SoulPrivacySDKConfig["addresses"];

    // Native ETH asset identifier (keccak256("ETH"))
    public static readonly NATIVE_ASSET: Hex = keccak256(toBytes("ETH"));

    constructor(config: SoulPrivacySDKConfig) {
        this.publicClient = config.publicClient;
        this.walletClient = config.walletClient;
        this.addresses = config.addresses;
    }

    /*//////////////////////////////////////////////////////////////
                        DEPOSIT OPERATIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * Generate a deposit note with random secret + nullifier preimage.
     * The commitment is H(secret || nullifier_preimage || amount || assetId).
     *
     * NOTE: In production, use the Noir circuit's Poseidon hash.
     * This uses keccak256 as a placeholder for off-chain note generation.
     */
    generateDepositNote(
        amount: bigint,
        assetId: Hex = SoulPrivacySDK.NATIVE_ASSET,
    ): DepositNote {
        // Generate random secret and nullifier preimage
        const secret = this._randomHex(32);
        const nullifierPreimage = this._randomHex(32);

        // Compute commitment using Poseidon hash (circuit-compatible)
        let commitment: Hex;
        try {
            // poseidon2 from poseidon-lite operates on bigints
            const { poseidon2 } = require("poseidon-lite");
            const secretBn = BigInt(secret);
            const nullBn = BigInt(nullifierPreimage);
            // First hash: H(secret, nullifier_preimage)
            const inner = poseidon2([secretBn, nullBn]);
            // Second hash: H(inner, amount) — assetId folded via XOR to keep arity=2
            const assetBn = BigInt(assetId);
            const h = poseidon2([inner, amount ^ assetBn]);
            commitment = `0x${h.toString(16).padStart(64, "0")}` as Hex;
        } catch {
            // Fallback to keccak256 if poseidon-lite not installed
            commitment = keccak256(
                encodePacked(
                    ["bytes32", "bytes32", "uint256", "bytes32"],
                    [secret as Hex, nullifierPreimage as Hex, amount, assetId],
                ),
            );
        }

        return {
            commitment,
            secret,
            nullifierPreimage,
            amount,
            assetId,
        };
    }

    /**
     * Deposit native ETH via the ShieldedPool (direct) or PrivacyRouter.
     * @returns Transaction hash
     */
    async depositETH(
        commitment: Hex,
        amount: bigint,
        useRouter = false,
    ): Promise<Hash> {
        this._requireWallet();

        const target = useRouter
            ? this.addresses.privacyRouter
            : this.addresses.shieldedPool;

        if (!target) throw new Error("No pool/router address configured");

        const abi = useRouter ? ROUTER_ABI : POOL_ABI;

        const hash = await this.walletClient!.writeContract({
            chain: this.walletClient!.chain ?? null,
            account: this.walletClient!.account!,
            address: target,
            abi,
            functionName: "depositETH",
            args: [commitment],
            value: amount,
        });

        return hash;
    }

    /**
     * Deposit ERC20 tokens via the ShieldedPool or PrivacyRouter.
     * @returns Transaction hash
     */
    async depositERC20(
        assetId: Hex,
        amount: bigint,
        commitment: Hex,
        useRouter = false,
    ): Promise<Hash> {
        this._requireWallet();

        const target = useRouter
            ? this.addresses.privacyRouter
            : this.addresses.shieldedPool;

        if (!target) throw new Error("No pool/router address configured");

        const abi = useRouter ? ROUTER_ABI : POOL_ABI;

        const hash = await this.walletClient!.writeContract({
            chain: this.walletClient!.chain ?? null,
            account: this.walletClient!.account!,
            address: target,
            abi,
            functionName: "depositERC20",
            args: [assetId, amount, commitment],
        });

        return hash;
    }

    /*//////////////////////////////////////////////////////////////
                        QUERY OPERATIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * Get pool statistics (total deposits, withdrawals, tree size, root).
     */
    async getPoolStats(): Promise<PoolStats> {
        const pool = this._requirePool();

        const result = await this.publicClient.readContract({
            address: pool,
            abi: POOL_ABI,
            functionName: "getPoolStats",
        });

        return {
            totalDeposits: result[0],
            totalWithdrawals: result[1],
            crossChainDeposits: result[2],
            treeSize: result[3],
            currentRoot: result[4],
        };
    }

    /**
     * Get the current Merkle root.
     */
    async getCurrentRoot(): Promise<Hex> {
        const pool = this._requirePool();
        return await this.publicClient.readContract({
            address: pool,
            abi: POOL_ABI,
            functionName: "currentRoot",
        });
    }

    /**
     * Check if a Merkle root is known (in history).
     */
    async isKnownRoot(root: Hex): Promise<boolean> {
        const pool = this._requirePool();
        return await this.publicClient.readContract({
            address: pool,
            abi: POOL_ABI,
            functionName: "isKnownRoot",
            args: [root],
        });
    }

    /**
     * Check if a nullifier has been spent (double-spend prevention).
     */
    async isNullifierSpent(nullifier: Hex): Promise<boolean> {
        const pool = this._requirePool();
        return await this.publicClient.readContract({
            address: pool,
            abi: POOL_ABI,
            functionName: "isSpent",
            args: [nullifier],
        });
    }

    /**
     * Get the next leaf index in the Merkle tree.
     */
    async getNextLeafIndex(): Promise<bigint> {
        const pool = this._requirePool();
        return await this.publicClient.readContract({
            address: pool,
            abi: POOL_ABI,
            functionName: "nextLeafIndex",
        });
    }

    /*//////////////////////////////////////////////////////////////
                       UTILITY / INTERNAL
    //////////////////////////////////////////////////////////////*/

    private _requireWallet(): void {
        if (!this.walletClient) {
            throw new Error("WalletClient required for write operations");
        }
    }

    private _requirePool(): Address {
        const pool = this.addresses.shieldedPool;
        if (!pool) throw new Error("ShieldedPool address not configured");
        return pool;
    }

    private _randomHex(bytes: number): Hex {
        const arr = new Uint8Array(bytes);
        if (typeof globalThis.crypto !== "undefined") {
            globalThis.crypto.getRandomValues(arr);
        } else {
            // Node.js fallback
            for (let i = 0; i < bytes; i++) {
                arr[i] = Math.floor(Math.random() * 256);
            }
        }
        return ("0x" +
            Array.from(arr)
                .map((b) => b.toString(16).padStart(2, "0"))
                .join("")) as Hex;
    }
}
