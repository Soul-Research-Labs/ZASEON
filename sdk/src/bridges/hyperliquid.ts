/**
 * Soul Protocol - Hyperliquid Bridge SDK Module
 *
 * TypeScript utilities and types for interacting with the HyperliquidBridgeAdapter contract.
 * Provides Hyperliquid-specific helpers: drip conversions, address validation,
 * fee calculations, Merkle proof construction, and escrow utilities.
 *
 * @example
 * ```typescript
 * import { hypeToDrips, dripsToHype, calculateHLBridgeFee, HYPERLIQUID_BRIDGE_ABI } from './hyperliquid';
 *
 * const amount = hypeToDrips(10); // 1_000_000_000n (10 HYPE in drips)
 * const fee = calculateHLBridgeFee(amount); // 150_000n (0.15%)
 * ```
 */

// =============================================================================
// CONSTANTS
// =============================================================================

/** 1 HYPE = 1e8 drips (8 decimals) */
export const DRIPS_PER_HYPE = 100_000_000n;

/** Minimum deposit: 0.1 HYPE */
export const HL_MIN_DEPOSIT_DRIPS = DRIPS_PER_HYPE / 10n;

/** Maximum deposit: 1,000,000 HYPE */
export const HL_MAX_DEPOSIT_DRIPS = 1_000_000n * DRIPS_PER_HYPE;

/** Bridge fee: 15 BPS (0.15%) */
export const HL_BRIDGE_FEE_BPS = 15n;

/** BPS denominator */
export const HL_BPS_DENOMINATOR = 10_000n;

/** Minimum escrow timelock: 30 minutes */
export const HL_MIN_ESCROW_TIMELOCK = 1800;

/** Maximum escrow timelock: 14 days */
export const HL_MAX_ESCROW_TIMELOCK = 14 * 24 * 3600;

/** Withdrawal refund delay: 24 hours */
export const HL_WITHDRAWAL_REFUND_DELAY = 24 * 3600;

/** Default block confirmations */
export const HL_DEFAULT_BLOCK_CONFIRMATIONS = 3;

/** Hyperliquid block time in ms (~200ms) */
export const HL_BLOCK_TIME_MS = 200;

/** Hyperliquid chain ID (HyperEVM mainnet) */
export const HYPERLIQUID_CHAIN_ID = 999;

/** Number of active HyperBFT validators */
export const HL_ACTIVE_VALIDATORS = 4;

/** BFT supermajority: 2/3+1 = 3 of 4 */
export const HL_SUPERMAJORITY = 3;

// =============================================================================
// ENUMS
// =============================================================================

export enum HYPEDepositStatus {
    PENDING = 0,
    VERIFIED = 1,
    COMPLETED = 2,
    FAILED = 3,
}

export enum HYPEWithdrawalStatus {
    PENDING = 0,
    PROCESSING = 1,
    COMPLETED = 2,
    REFUNDED = 3,
    FAILED = 4,
}

export enum HYPEEscrowStatus {
    ACTIVE = 0,
    FINISHED = 1,
    CANCELLED = 2,
}

export enum HyperliquidTxType {
    TRANSFER = 0,
    SPOT_TRANSFER = 1,
    CONTRACT_CALL = 2,
    CROSS_CHAIN = 3,
}

// =============================================================================
// TYPES
// =============================================================================

export interface HYPEDeposit {
    depositId: `0x${string}`;
    hlTxHash: `0x${string}`;
    hlSender: `0x${string}`;
    evmRecipient: `0x${string}`;
    amountDrips: bigint;
    netAmountDrips: bigint;
    fee: bigint;
    status: HYPEDepositStatus;
    blockNumber: bigint;
    initiatedAt: bigint;
    completedAt: bigint;
}

export interface HYPEWithdrawal {
    withdrawalId: `0x${string}`;
    evmSender: `0x${string}`;
    hlRecipient: `0x${string}`;
    amountDrips: bigint;
    hlTxHash: `0x${string}`;
    status: HYPEWithdrawalStatus;
    initiatedAt: bigint;
    completedAt: bigint;
}

export interface HYPEEscrow {
    escrowId: `0x${string}`;
    evmParty: `0x${string}`;
    hlParty: `0x${string}`;
    amountDrips: bigint;
    hashlock: `0x${string}`;
    preimage: `0x${string}`;
    finishAfter: bigint;
    cancelAfter: bigint;
    status: HYPEEscrowStatus;
    createdAt: bigint;
}

export interface HyperliquidBridgeConfig {
    hyperliquidBridgeContract: `0x${string}`;
    wrappedHYPE: `0x${string}`;
    validatorOracle: `0x${string}`;
    minValidatorSignatures: bigint;
    requiredBlockConfirmations: bigint;
    active: boolean;
}

export interface HyperBFTBlockHeader {
    blockNumber: bigint;
    blockHash: `0x${string}`;
    parentHash: `0x${string}`;
    transactionsRoot: `0x${string}`;
    stateRoot: `0x${string}`;
    blockTime: bigint;
    finalized: boolean;
}

export interface HLValidatorAttestation {
    validator: `0x${string}`;
    signature: `0x${string}`;
}

export interface HyperliquidMerkleProof {
    leafHash: `0x${string}`;
    proof: `0x${string}`[];
    index: bigint;
}

export interface HyperliquidBridgeStats {
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
 * Convert HYPE to drips (smallest unit)
 * @param hype Amount in HYPE (supports decimals as string)
 * @returns Amount in drips as bigint
 */
export function hypeToDrips(hype: number | string): bigint {
    if (typeof hype === 'string') {
        const parts = hype.split('.');
        const whole = BigInt(parts[0]) * DRIPS_PER_HYPE;
        if (parts.length === 1) return whole;

        const decStr = parts[1].padEnd(8, '0').slice(0, 8);
        return whole + BigInt(decStr);
    }
    return hypeToDrips(hype.toString());
}

/**
 * Convert drips to HYPE string
 * @param drips Amount in drips
 * @returns Formatted HYPE amount string (up to 8 decimals)
 */
export function dripsToHype(drips: bigint): string {
    const whole = drips / DRIPS_PER_HYPE;
    const remainder = drips % DRIPS_PER_HYPE;

    if (remainder === 0n) return whole.toString();

    const fracStr = remainder.toString().padStart(8, '0').replace(/0+$/, '');
    return `${whole}.${fracStr}`;
}

/**
 * Format drips as human-readable string with units
 * @param drips Amount in drips
 * @returns e.g. "1.5 HYPE" or "500,000 drips"
 */
export function formatHYPEDrips(drips: bigint): string {
    if (drips >= DRIPS_PER_HYPE) {
        return `${dripsToHype(drips)} HYPE`;
    }
    return `${drips.toLocaleString()} drips`;
}

// =============================================================================
// VALIDATION UTILITIES
// =============================================================================

/**
 * Validate an EVM address (HyperEVM is EVM-compatible)
 * @param address HyperEVM/EVM address string
 * @returns True if the address format is valid
 */
export function isValidHLAddress(address: string): boolean {
    return /^0x[0-9a-fA-F]{40}$/.test(address);
}

/**
 * Validate a deposit amount is within bridge limits
 * @param amountDrips Amount in drips
 * @returns Object with valid flag and error message if invalid
 */
export function validateHYPEDepositAmount(amountDrips: bigint): {
    valid: boolean;
    error?: string;
} {
    if (amountDrips < HL_MIN_DEPOSIT_DRIPS) {
        return {
            valid: false,
            error: `Amount ${formatHYPEDrips(amountDrips)} is below minimum deposit of ${formatHYPEDrips(HL_MIN_DEPOSIT_DRIPS)}`,
        };
    }
    if (amountDrips > HL_MAX_DEPOSIT_DRIPS) {
        return {
            valid: false,
            error: `Amount ${formatHYPEDrips(amountDrips)} exceeds maximum deposit of ${formatHYPEDrips(HL_MAX_DEPOSIT_DRIPS)}`,
        };
    }
    return { valid: true };
}

// =============================================================================
// FEE CALCULATIONS
// =============================================================================

/**
 * Calculate the bridge fee for a given amount
 * @param amountDrips Gross amount in drips
 * @returns Fee in drips (0.15% by default)
 */
export function calculateHLBridgeFee(amountDrips: bigint): bigint {
    return (amountDrips * HL_BRIDGE_FEE_BPS) / HL_BPS_DENOMINATOR;
}

/**
 * Calculate the net amount after bridge fee
 * @param amountDrips Gross amount in drips
 * @returns Net amount in drips
 */
export function calculateHLNetAmount(amountDrips: bigint): bigint {
    return amountDrips - calculateHLBridgeFee(amountDrips);
}

// =============================================================================
// ESCROW UTILITIES
// =============================================================================

/**
 * Generate a random preimage for HTLC escrow
 * @returns 32-byte hex preimage
 */
export function generateHLPreimage(): `0x${string}` {
    const bytes = new Uint8Array(32);
    crypto.getRandomValues(bytes);
    return `0x${Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('')}`;
}

/**
 * Compute the SHA-256 hashlock from a preimage
 * @param preimage The 32-byte hex preimage
 * @returns SHA-256 hash of the preimage
 */
export async function computeHLHashlock(preimage: `0x${string}`): Promise<`0x${string}`> {
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
export function validateHLEscrowTimelocks(
    finishAfter: number,
    cancelAfter: number
): { valid: boolean; error?: string } {
    const now = Math.floor(Date.now() / 1000);

    if (finishAfter <= now) {
        return { valid: false, error: 'finishAfter must be in the future' };
    }

    const duration = cancelAfter - finishAfter;

    if (duration < HL_MIN_ESCROW_TIMELOCK) {
        return {
            valid: false,
            error: `Escrow duration ${duration}s is below minimum ${HL_MIN_ESCROW_TIMELOCK}s (30 minutes)`,
        };
    }

    if (duration > HL_MAX_ESCROW_TIMELOCK) {
        return {
            valid: false,
            error: `Escrow duration ${duration}s exceeds maximum ${HL_MAX_ESCROW_TIMELOCK}s (14 days)`,
        };
    }

    return { valid: true };
}

// =============================================================================
// TIMING UTILITIES
// =============================================================================

/**
 * Estimate confirmation time for a given number of block confirmations
 * @param blockConfirmations Number of block confirmations required
 * @returns Estimated time in seconds
 */
export function estimateHLConfirmationTime(
    blockConfirmations: number = HL_DEFAULT_BLOCK_CONFIRMATIONS
): number {
    return Math.ceil((blockConfirmations * HL_BLOCK_TIME_MS) / 1000);
}

/**
 * Check if a withdrawal is eligible for refund
 * @param initiatedAt Timestamp when withdrawal was initiated (UNIX seconds)
 * @returns True if the refund delay has passed
 */
export function isHLRefundEligible(initiatedAt: number): boolean {
    const now = Math.floor(Date.now() / 1000);
    return now >= initiatedAt + HL_WITHDRAWAL_REFUND_DELAY;
}

/**
 * Estimate BFT finality time in milliseconds
 * @returns Estimated finality time (~600ms for 3 blocks)
 */
export function estimateHLFinalityMs(): number {
    return HL_DEFAULT_BLOCK_CONFIRMATIONS * HL_BLOCK_TIME_MS;
}

// =============================================================================
// ABI FRAGMENTS
// =============================================================================

export const HYPERLIQUID_BRIDGE_ABI = [
    // Configuration
    'function configure(address hyperliquidBridgeContract, address wrappedHYPE, address validatorOracle, uint256 minValidatorSignatures, uint256 requiredBlockConfirmations) external',
    'function setTreasury(address _treasury) external',

    // Deposits (Hyperliquid → Soul)
    'function initiateHYPEDeposit(bytes32 hlTxHash, address hlSender, address evmRecipient, uint256 amountDrips, uint256 blockNumber, (bytes32 leafHash, bytes32[] proof, uint256 index) txProof, (address validator, bytes signature)[] attestations) external returns (bytes32)',
    'function completeHYPEDeposit(bytes32 depositId) external',

    // Withdrawals (Soul → Hyperliquid)
    'function initiateWithdrawal(address hlRecipient, uint256 amountDrips) external returns (bytes32)',
    'function completeWithdrawal(bytes32 withdrawalId, bytes32 hlTxHash, (bytes32 leafHash, bytes32[] proof, uint256 index) txProof, (address validator, bytes signature)[] attestations) external',
    'function refundWithdrawal(bytes32 withdrawalId) external',

    // Escrow (Atomic Swaps)
    'function createEscrow(address hlParty, bytes32 hashlock, uint256 finishAfter, uint256 cancelAfter) external payable returns (bytes32)',
    'function finishEscrow(bytes32 escrowId, bytes32 preimage) external',
    'function cancelEscrow(bytes32 escrowId) external',

    // Privacy
    'function registerPrivateDeposit(bytes32 depositId, bytes32 commitment, bytes32 nullifier, bytes zkProof) external',

    // Block Headers (no receiptsRoot — Hyperliquid HyperBFT)
    'function submitBlockHeader(uint256 blockNumber, bytes32 blockHash, bytes32 parentHash, bytes32 transactionsRoot, bytes32 stateRoot, uint256 blockTime, (address validator, bytes signature)[] attestations) external',

    // Views
    'function getDeposit(bytes32 depositId) external view returns (tuple)',
    'function getWithdrawal(bytes32 withdrawalId) external view returns (tuple)',
    'function getEscrow(bytes32 escrowId) external view returns (tuple)',
    'function getBlockHeader(uint256 blockNumber) external view returns (tuple)',
    'function getUserDeposits(address user) external view returns (bytes32[])',
    'function getUserWithdrawals(address user) external view returns (bytes32[])',
    'function getUserEscrows(address user) external view returns (bytes32[])',
    'function getBridgeStats() external view returns (uint256, uint256, uint256, uint256, uint256, uint256, uint256)',

    // Admin
    'function pause() external',
    'function unpause() external',
    'function withdrawFees() external',

    // Constants
    'function HYPERLIQUID_CHAIN_ID() view returns (uint256)',
    'function DRIPS_PER_HYPE() view returns (uint256)',
    'function MIN_DEPOSIT_DRIPS() view returns (uint256)',
    'function MAX_DEPOSIT_DRIPS() view returns (uint256)',
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
    'function usedHLTxHashes(bytes32) view returns (bool)',
    'function usedNullifiers(bytes32) view returns (bool)',

    // Events
    'event BridgeConfigured(address indexed hyperliquidBridgeContract, address wrappedHYPE, address validatorOracle)',
    'event HYPEDepositInitiated(bytes32 indexed depositId, bytes32 indexed hlTxHash, address hlSender, address indexed evmRecipient, uint256 amountDrips)',
    'event HYPEDepositCompleted(bytes32 indexed depositId, address indexed evmRecipient, uint256 amountDrips)',
    'event HYPEWithdrawalInitiated(bytes32 indexed withdrawalId, address indexed evmSender, address hlRecipient, uint256 amountDrips)',
    'event HYPEWithdrawalCompleted(bytes32 indexed withdrawalId, bytes32 hlTxHash)',
    'event HYPEWithdrawalRefunded(bytes32 indexed withdrawalId, address indexed evmSender, uint256 amountDrips)',
    'event EscrowCreated(bytes32 indexed escrowId, address indexed evmParty, address hlParty, uint256 amountDrips, bytes32 hashlock)',
    'event EscrowFinished(bytes32 indexed escrowId, bytes32 preimage)',
    'event EscrowCancelled(bytes32 indexed escrowId)',
    'event BlockHeaderSubmitted(uint256 indexed blockNumber, bytes32 blockHash)',
    'event PrivateDepositRegistered(bytes32 indexed depositId, bytes32 commitment, bytes32 nullifier)',
    'event FeesWithdrawn(address indexed recipient, uint256 amount)',
] as const;

export const WRAPPED_HYPE_ABI = [
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
