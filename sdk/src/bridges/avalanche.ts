/**
 * Soul Protocol - Avalanche Bridge SDK Module
 *
 * TypeScript utilities and types for interacting with the AvalancheBridgeAdapter contract.
 * Provides Avalanche C-Chain-specific helpers: wei/nAVAX conversions, address validation,
 * fee calculations, Warp message utilities, and escrow helpers.
 *
 * Avalanche is a Layer 1 blockchain platform featuring the Snowman consensus protocol
 * for the C-Chain (Contract Chain), an EVM-compatible execution environment with
 * ~2s block finality. It supports Avalanche Warp Messaging (AWM) for native
 * cross-subnet communication and uses 18-decimal precision (wei/nAVAX).
 *
 * @example
 * ```typescript
 * import { avaxToWei, weiToAvax, calculateAvalancheBridgeFee, AVALANCHE_BRIDGE_ABI } from './avalanche';
 *
 * const amount = avaxToWei(10); // 10_000_000_000_000_000_000n (10 AVAX in wei)
 * const fee = calculateAvalancheBridgeFee(amount); // 0.04%
 * ```
 */

// =============================================================================
// CONSTANTS
// =============================================================================

/** 1 AVAX = 1e18 wei (18 decimals, standard EVM) */
export const WEI_PER_AVAX = 10n ** 18n;

/** 1 AVAX = 1e9 nAVAX (9 decimals, Avalanche naming convention) */
export const NAVAX_PER_AVAX = 10n ** 9n;

/** Minimum deposit: 0.01 AVAX (in wei) */
export const AVAX_MIN_DEPOSIT = 10n ** 16n;

/** Maximum deposit: 10,000,000 AVAX (in wei) */
export const AVAX_MAX_DEPOSIT = 10_000_000n * WEI_PER_AVAX;

/** Bridge fee: 4 BPS (0.04%) */
export const AVAX_BRIDGE_FEE_BPS = 4n;

/** BPS denominator */
export const AVAX_BPS_DENOMINATOR = 10_000n;

/** Minimum escrow timelock: 1 hour */
export const AVAX_MIN_ESCROW_TIMELOCK = 3600;

/** Maximum escrow timelock: 14 days */
export const AVAX_MAX_ESCROW_TIMELOCK = 14 * 24 * 3600;

/** Withdrawal refund delay: 24 hours */
export const AVAX_WITHDRAWAL_REFUND_DELAY = 24 * 3600;

/** Default block confirmations for finality */
export const AVAX_DEFAULT_BLOCK_CONFIRMATIONS = 1;

/** Avalanche C-Chain block time in ms (~2s Snowman consensus) */
export const AVAX_BLOCK_TIME_MS = 2000;

/** Avalanche C-Chain mainnet chain ID */
export const AVALANCHE_CHAIN_ID = 43114;

/** Avalanche epoch duration (~24 hours) */
export const AVALANCHE_EPOCH_DURATION_MS = 24 * 60 * 60 * 1000;

// =============================================================================
// ENUMS
// =============================================================================

export enum AVAXDepositStatus {
    PENDING = 0,
    VERIFIED = 1,
    COMPLETED = 2,
    FAILED = 3,
}

export enum AVAXWithdrawalStatus {
    PENDING = 0,
    PROCESSING = 1,
    COMPLETED = 2,
    REFUNDED = 3,
    FAILED = 4,
}

export enum AVAXEscrowStatus {
    ACTIVE = 0,
    FINISHED = 1,
    CANCELLED = 2,
}

export enum AvalancheBridgeOpType {
    NATIVE_TRANSFER = 0,
    ERC20_TRANSFER = 1,
    WARP_MESSAGE = 2,
    EMERGENCY_OP = 3,
}

// =============================================================================
// TYPES
// =============================================================================

export interface AVAXDeposit {
    depositId: `0x${string}`;
    cChainTxHash: `0x${string}`;
    cChainSender: `0x${string}`; // 20-byte EVM address
    evmRecipient: `0x${string}`;
    amountWei: bigint;
    netAmountWei: bigint;
    fee: bigint;
    status: AVAXDepositStatus;
    blockNumber: bigint;
    initiatedAt: bigint;
    completedAt: bigint;
}

export interface AVAXWithdrawal {
    withdrawalId: `0x${string}`;
    evmSender: `0x${string}`;
    cChainRecipient: `0x${string}`; // 20-byte EVM address
    amountWei: bigint;
    cChainTxHash: `0x${string}`;
    status: AVAXWithdrawalStatus;
    initiatedAt: bigint;
    completedAt: bigint;
}

export interface AVAXEscrow {
    escrowId: `0x${string}`;
    evmParty: `0x${string}`;
    cChainParty: `0x${string}`; // 20-byte EVM address
    amountWei: bigint;
    hashlock: `0x${string}`;
    preimage: `0x${string}`;
    finishAfter: bigint;
    cancelAfter: bigint;
    status: AVAXEscrowStatus;
    createdAt: bigint;
}

export interface AvalancheBridgeConfig {
    avalancheBridgeContract: `0x${string}`;
    wrappedAVAX: `0x${string}`;
    warpMessenger: `0x${string}`;
    minValidatorSignatures: bigint;
    requiredBlockConfirmations: bigint;
    active: boolean;
}

export interface SnowmanBlock {
    blockNumber: bigint;
    blockHash: `0x${string}`;
    parentHash: `0x${string}`;
    stateRoot: `0x${string}`;
    timestamp: bigint;
    verified: boolean;
}

export interface WarpStateProof {
    merkleProof: `0x${string}`[];
    blockIndex: bigint;
    leafHash: `0x${string}`;
}

export interface AvalancheBridgeStats {
    totalDeposited: bigint;
    totalWithdrawn: bigint;
    totalEscrows: bigint;
    totalEscrowsFinished: bigint;
    totalEscrowsCancelled: bigint;
    accumulatedFees: bigint;
    latestBlockNumber: bigint;
}

// =============================================================================
// CONVERSION UTILITIES
// =============================================================================

/**
 * Convert AVAX to wei (smallest unit, 18 decimals)
 * @param avax Amount in AVAX (supports decimals as string)
 * @returns Amount in wei as bigint
 */
export function avaxToWei(avax: number | string): bigint {
    if (typeof avax === 'string') {
        const parts = avax.split('.');
        const whole = BigInt(parts[0]) * WEI_PER_AVAX;
        if (parts.length === 1) return whole;

        const decStr = parts[1].padEnd(18, '0').slice(0, 18);
        return whole + BigInt(decStr);
    }
    return avaxToWei(avax.toString());
}

/**
 * Convert wei to AVAX string
 * @param wei Amount in wei
 * @returns Formatted AVAX amount string (up to 18 decimals)
 */
export function weiToAvax(wei: bigint): string {
    const whole = wei / WEI_PER_AVAX;
    const remainder = wei % WEI_PER_AVAX;

    if (remainder === 0n) return whole.toString();

    const fracStr = remainder.toString().padStart(18, '0').replace(/0+$/, '');
    return `${whole}.${fracStr}`;
}

/**
 * Convert AVAX to nAVAX (9-decimal Avalanche convention)
 * @param avax Amount in AVAX (supports decimals as string)
 * @returns Amount in nAVAX as bigint
 */
export function avaxToNavax(avax: number | string): bigint {
    if (typeof avax === 'string') {
        const parts = avax.split('.');
        const whole = BigInt(parts[0]) * NAVAX_PER_AVAX;
        if (parts.length === 1) return whole;

        const decStr = parts[1].padEnd(9, '0').slice(0, 9);
        return whole + BigInt(decStr);
    }
    return avaxToNavax(avax.toString());
}

/**
 * Format wei as human-readable string with units
 * @param wei Amount in wei
 * @returns e.g. "1.5 AVAX" or "500,000 wei"
 */
export function formatAVAXWei(wei: bigint): string {
    if (wei >= WEI_PER_AVAX) {
        return `${weiToAvax(wei)} AVAX`;
    }
    return `${wei.toLocaleString()} wei`;
}

// =============================================================================
// VALIDATION UTILITIES
// =============================================================================

/**
 * Validate an Avalanche C-Chain address (EVM-compatible, 20-byte, 0x-prefixed)
 * @param address C-Chain address string
 * @returns True if the address format appears valid
 */
export function isValidCChainAddress(address: string): boolean {
    return /^0x[0-9a-fA-F]{40}$/.test(address);
}

/**
 * Validate a deposit amount is within bridge limits
 * @param amountWei Amount in wei
 * @returns Object with valid flag and error message if invalid
 */
export function validateAVAXDepositAmount(amountWei: bigint): {
    valid: boolean;
    error?: string;
} {
    if (amountWei < AVAX_MIN_DEPOSIT) {
        return {
            valid: false,
            error: `Amount ${formatAVAXWei(amountWei)} is below minimum deposit of ${formatAVAXWei(AVAX_MIN_DEPOSIT)}`,
        };
    }
    if (amountWei > AVAX_MAX_DEPOSIT) {
        return {
            valid: false,
            error: `Amount ${formatAVAXWei(amountWei)} exceeds maximum deposit of ${formatAVAXWei(AVAX_MAX_DEPOSIT)}`,
        };
    }
    return { valid: true };
}

// =============================================================================
// FEE CALCULATIONS
// =============================================================================

/**
 * Calculate the bridge fee for a given amount
 * @param amountWei Gross amount in wei
 * @returns Fee in wei (0.04% by default)
 */
export function calculateAvalancheBridgeFee(amountWei: bigint): bigint {
    return (amountWei * AVAX_BRIDGE_FEE_BPS) / AVAX_BPS_DENOMINATOR;
}

/**
 * Calculate the net amount after bridge fee
 * @param amountWei Gross amount in wei
 * @returns Net amount in wei
 */
export function calculateAvalancheNetAmount(amountWei: bigint): bigint {
    return amountWei - calculateAvalancheBridgeFee(amountWei);
}

// =============================================================================
// ESCROW UTILITIES
// =============================================================================

/**
 * Generate a random preimage for HTLC escrow
 * @returns 32-byte hex preimage
 */
export function generateAvalanchePreimage(): `0x${string}` {
    const bytes = new Uint8Array(32);
    crypto.getRandomValues(bytes);
    return `0x${Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('')}`;
}

/**
 * Compute the SHA-256 hashlock from a preimage
 * @param preimage The 32-byte hex preimage
 * @returns SHA-256 hash of the preimage
 */
export async function computeAvalancheHashlock(preimage: `0x${string}`): Promise<`0x${string}`> {
    const bytes = new Uint8Array(
        (preimage.slice(2).match(/.{2}/g) || []).map((b) => parseInt(b, 16))
    );
    const hash = await crypto.subtle.digest('SHA-256', bytes);
    return `0x${Array.from(new Uint8Array(hash)).map((b) => b.toString(16).padStart(2, '0')).join('')}`;
}

/**
 * Validate escrow timelock parameters
 * @param finishAfter Earliest finish time (UNIX seconds)
 * @param cancelAfter Earliest cancel time (UNIX seconds)
 * @returns Validation result
 */
export function validateAvalancheEscrowTimelocks(
    finishAfter: number,
    cancelAfter: number
): { valid: boolean; error?: string } {
    const now = Math.floor(Date.now() / 1000);

    if (finishAfter <= now) {
        return { valid: false, error: 'finishAfter must be in the future' };
    }

    const duration = cancelAfter - finishAfter;

    if (duration < AVAX_MIN_ESCROW_TIMELOCK) {
        return {
            valid: false,
            error: `Escrow duration ${duration}s is below minimum ${AVAX_MIN_ESCROW_TIMELOCK}s (1 hour)`,
        };
    }

    if (duration > AVAX_MAX_ESCROW_TIMELOCK) {
        return {
            valid: false,
            error: `Escrow duration ${duration}s exceeds maximum ${AVAX_MAX_ESCROW_TIMELOCK}s (14 days)`,
        };
    }

    return { valid: true };
}

// =============================================================================
// TIMING UTILITIES
// =============================================================================

/**
 * Estimate block finalization time on C-Chain
 * @param confirmations Number of block confirmations (default: 1)
 * @returns Estimated time in milliseconds
 */
export function estimateAvalancheBlockFinalityMs(confirmations?: number): number {
    const n = confirmations ?? AVAX_DEFAULT_BLOCK_CONFIRMATIONS;
    return n * AVAX_BLOCK_TIME_MS;
}

/**
 * Check if a withdrawal is eligible for refund
 * @param initiatedAt Timestamp when withdrawal was initiated (UNIX seconds)
 * @returns True if the refund delay (24 hours) has passed
 */
export function isAvalancheRefundEligible(initiatedAt: number): boolean {
    const now = Math.floor(Date.now() / 1000);
    return now >= initiatedAt + AVAX_WITHDRAWAL_REFUND_DELAY;
}

/**
 * Estimate remaining time until epoch change
 * @param epochStartMs Epoch start time in milliseconds
 * @returns Remaining time in milliseconds (0 if epoch should have ended)
 */
export function estimateAvalancheRemainingEpochMs(epochStartMs: number): number {
    const now = Date.now();
    const epochEnd = epochStartMs + AVALANCHE_EPOCH_DURATION_MS;
    return Math.max(0, epochEnd - now);
}

/**
 * Estimate time for a given number of Snowman consensus rounds
 * @param blocks Number of blocks
 * @returns Estimated time in milliseconds
 */
export function estimateAvalancheConsensusTimeMs(blocks: number): number {
    return blocks * AVAX_BLOCK_TIME_MS;
}

// =============================================================================
// ABI FRAGMENTS
// =============================================================================

export const AVALANCHE_BRIDGE_ABI = [
    // Configuration
    'function configure(address avalancheBridgeContract, address wrappedAVAX, address warpMessenger, uint256 minValidatorSignatures, uint256 requiredBlockConfirmations) external',
    'function setTreasury(address _treasury) external',

    // Deposits (C-Chain → Soul)
    'function initiateAVAXDeposit(bytes32 cChainTxHash, address cChainSender, address evmRecipient, uint256 amountWei, uint256 blockNumber, (bytes32[] merkleProof, uint256 blockIndex, bytes32 leafHash) stateProof, (address validator, bytes signature)[] attestations) external returns (bytes32)',
    'function completeAVAXDeposit(bytes32 depositId) external',

    // Withdrawals (Soul → C-Chain)
    'function initiateWithdrawal(address cChainRecipient, uint256 amountWei) external returns (bytes32)',
    'function completeWithdrawal(bytes32 withdrawalId, bytes32 cChainTxHash, (bytes32[] merkleProof, uint256 blockIndex, bytes32 leafHash) stateProof, (address validator, bytes signature)[] attestations) external',
    'function refundWithdrawal(bytes32 withdrawalId) external',

    // Escrow (Atomic Swaps)
    'function createEscrow(address cChainParty, bytes32 hashlock, uint256 finishAfter, uint256 cancelAfter) external payable returns (bytes32)',
    'function finishEscrow(bytes32 escrowId, bytes32 preimage) external',
    'function cancelEscrow(bytes32 escrowId) external',

    // Privacy
    'function registerPrivateDeposit(bytes32 depositId, bytes32 commitment, bytes32 nullifier, bytes zkProof) external',

    // Block Verification
    'function submitSnowmanBlock(uint256 blockNumber, bytes32 blockHash, bytes32 parentHash, bytes32 stateRoot, uint256 timestamp, (address validator, bytes signature)[] attestations) external',

    // Views
    'function getDeposit(bytes32 depositId) external view returns (tuple)',
    'function getWithdrawal(bytes32 withdrawalId) external view returns (tuple)',
    'function getEscrow(bytes32 escrowId) external view returns (tuple)',
    'function getSnowmanBlock(uint256 blockNumber) external view returns (tuple)',
    'function getUserDeposits(address user) external view returns (bytes32[])',
    'function getUserWithdrawals(address user) external view returns (bytes32[])',
    'function getUserEscrows(address user) external view returns (bytes32[])',
    'function getBridgeStats() external view returns (uint256, uint256, uint256, uint256, uint256, uint256, uint256)',

    // Admin
    'function pause() external',
    'function unpause() external',
    'function withdrawFees() external',

    // Constants
    'function AVALANCHE_CHAIN_ID() view returns (uint256)',
    'function WEI_PER_AVAX() view returns (uint256)',
    'function MIN_DEPOSIT() view returns (uint256)',
    'function MAX_DEPOSIT() view returns (uint256)',
    'function BRIDGE_FEE_BPS() view returns (uint256)',
    'function WITHDRAWAL_REFUND_DELAY() view returns (uint256)',
    'function DEFAULT_BLOCK_CONFIRMATIONS() view returns (uint256)',

    // State
    'function depositNonce() view returns (uint256)',
    'function withdrawalNonce() view returns (uint256)',
    'function escrowNonce() view returns (uint256)',
    'function latestBlockNumber() view returns (uint256)',
    'function totalDeposited() view returns (uint256)',
    'function totalWithdrawn() view returns (uint256)',
    'function accumulatedFees() view returns (uint256)',
    'function treasury() view returns (address)',
    'function usedCChainTxHashes(bytes32) view returns (bool)',
    'function usedNullifiers(bytes32) view returns (bool)',

    // Events
    'event BridgeConfigured(address indexed avalancheBridgeContract, address wrappedAVAX, address warpMessenger)',
    'event AVAXDepositInitiated(bytes32 indexed depositId, bytes32 indexed cChainTxHash, address cChainSender, address indexed evmRecipient, uint256 amountWei)',
    'event AVAXDepositCompleted(bytes32 indexed depositId, address indexed evmRecipient, uint256 amountWei)',
    'event AVAXWithdrawalInitiated(bytes32 indexed withdrawalId, address indexed evmSender, address cChainRecipient, uint256 amountWei)',
    'event AVAXWithdrawalCompleted(bytes32 indexed withdrawalId, bytes32 cChainTxHash)',
    'event AVAXWithdrawalRefunded(bytes32 indexed withdrawalId, address indexed evmSender, uint256 amountWei)',
    'event EscrowCreated(bytes32 indexed escrowId, address indexed evmParty, address cChainParty, uint256 amountWei, bytes32 hashlock)',
    'event EscrowFinished(bytes32 indexed escrowId, bytes32 preimage)',
    'event EscrowCancelled(bytes32 indexed escrowId)',
    'event SnowmanBlockVerified(uint256 indexed blockNumber, bytes32 blockHash, uint256 timestamp)',
    'event PrivateDepositRegistered(bytes32 indexed depositId, bytes32 commitment, bytes32 nullifier)',
    'event FeesWithdrawn(address indexed recipient, uint256 amount)',
] as const;

export const WRAPPED_AVAX_ABI = [
    'function mint(address to, uint256 amount) external',
    'function burn(uint256 amount) external',
    'function balanceOf(address account) view returns (uint256)',
    'function approve(address spender, uint256 amount) returns (bool)',
    'function transfer(address to, uint256 amount) returns (bool)',
    'function transferFrom(address from, address to, uint256 amount) returns (bool)',
    'function allowance(address owner, address spender) view returns (uint256)',
    'function decimals() view returns (uint8)',
    'function totalSupply() view returns (uint256)',
] as const;
