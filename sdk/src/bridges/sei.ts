/**
 * Soul Protocol - Sei Bridge SDK Module
 *
 * TypeScript utilities and types for interacting with the SeiBridgeAdapter contract.
 * Provides Sei-specific helpers: usei conversions, address validation,
 * fee calculations, block header utilities, and escrow helpers.
 *
 * Sei is a Layer 1 blockchain optimized for trading/DeFi, featuring Twin-Turbo
 * consensus (optimistic block processing + intelligent block propagation) with
 * ~400ms block times, parallel EVM execution, built-in order book module,
 * and 6-decimal precision (usei).
 *
 * @example
 * ```typescript
 * import { seiToUsei, useiToSei, calculateSeiBridgeFee, SEI_BRIDGE_ABI } from './sei';
 *
 * const amount = seiToUsei(10); // 10_000_000n (10 SEI in usei)
 * const fee = calculateSeiBridgeFee(amount); // 5_000n (0.05%)
 * ```
 */

// =============================================================================
// CONSTANTS
// =============================================================================

/** 1 SEI = 1e6 usei (6 decimals) */
export const USEI_PER_SEI = 1_000_000n;

/** Minimum deposit: 0.1 SEI (100,000 usei) */
export const SEI_MIN_DEPOSIT_USEI = USEI_PER_SEI / 10n;

/** Maximum deposit: 10,000,000 SEI */
export const SEI_MAX_DEPOSIT_USEI = 10_000_000n * USEI_PER_SEI;

/** Bridge fee: 5 BPS (0.05%) */
export const SEI_BRIDGE_FEE_BPS = 5n;

/** BPS denominator */
export const SEI_BPS_DENOMINATOR = 10_000n;

/** Minimum escrow timelock: 1 hour */
export const SEI_MIN_ESCROW_TIMELOCK = 3600;

/** Maximum escrow timelock: 30 days */
export const SEI_MAX_ESCROW_TIMELOCK = 30 * 24 * 3600;

/** Withdrawal refund delay: 36 hours */
export const SEI_WITHDRAWAL_REFUND_DELAY = 36 * 3600;

/** Default block confirmations for finality */
export const SEI_DEFAULT_BLOCK_CONFIRMATIONS = 8;

/** Sei block time in ms (~400ms Twin-Turbo consensus) */
export const SEI_BLOCK_TIME_MS = 400;

/** Sei chain ID (sei-mainnet EVM) */
export const SEI_CHAIN_ID = 1329;

// =============================================================================
// ENUMS
// =============================================================================

export enum SEIDepositStatus {
    PENDING = 0,
    VERIFIED = 1,
    COMPLETED = 2,
    FAILED = 3,
}

export enum SEIWithdrawalStatus {
    PENDING = 0,
    PROCESSING = 1,
    COMPLETED = 2,
    REFUNDED = 3,
    FAILED = 4,
}

export enum SEIEscrowStatus {
    ACTIVE = 0,
    FINISHED = 1,
    CANCELLED = 2,
}

export enum SeiBridgeOpType {
    TOKEN_TRANSFER = 0,
    EVM_INTEROP = 1,
    ORDER_BOOK_SETTLE = 2,
    EMERGENCY_OP = 3,
}

// =============================================================================
// TYPES
// =============================================================================

export interface SEIDeposit {
    depositId: `0x${string}`;
    seiTxHash: `0x${string}`;
    seiSender: `0x${string}`; // 32-byte Sei address
    evmRecipient: `0x${string}`;
    amountUsei: bigint;
    netAmountUsei: bigint;
    fee: bigint;
    status: SEIDepositStatus;
    blockHeight: bigint;
    initiatedAt: bigint;
    completedAt: bigint;
}

export interface SEIWithdrawal {
    withdrawalId: `0x${string}`;
    evmSender: `0x${string}`;
    seiRecipient: `0x${string}`; // 32-byte Sei address
    amountUsei: bigint;
    seiTxHash: `0x${string}`;
    status: SEIWithdrawalStatus;
    initiatedAt: bigint;
    completedAt: bigint;
}

export interface SEIEscrow {
    escrowId: `0x${string}`;
    evmParty: `0x${string}`;
    seiParty: `0x${string}`; // 32-byte Sei address
    amountUsei: bigint;
    hashlock: `0x${string}`;
    preimage: `0x${string}`;
    finishAfter: bigint;
    cancelAfter: bigint;
    status: SEIEscrowStatus;
    createdAt: bigint;
}

export interface SeiBridgeConfig {
    seiBridgeContract: `0x${string}`;
    wrappedSEI: `0x${string}`;
    validatorOracle: `0x${string}`;
    minValidatorSignatures: bigint;
    requiredBlockConfirmations: bigint;
    active: boolean;
}

export interface SeiBlockHeader {
    height: bigint;
    blockHash: `0x${string}`;
    parentHash: `0x${string}`;
    stateRoot: `0x${string}`;
    txRoot: `0x${string}`;
    validatorSetHash: `0x${string}`;
    timestamp: bigint;
    numTxs: bigint;
    verified: boolean;
}

export interface ValidatorAttestation {
    validator: `0x${string}`; // EVM-compatible address
    signature: `0x${string}`;
}

export interface SeiMerkleProof {
    leafHash: `0x${string}`;
    proof: `0x${string}`[];
    index: bigint;
}

export interface SeiBridgeStats {
    totalDeposited: bigint;
    totalWithdrawn: bigint;
    totalEscrows: bigint;
    totalEscrowsFinished: bigint;
    totalEscrowsCancelled: bigint;
    accumulatedFees: bigint;
    latestBlockHeight: bigint;
}

// =============================================================================
// CONVERSION UTILITIES
// =============================================================================

/**
 * Convert SEI to usei (smallest unit)
 * @param sei Amount in SEI (supports decimals as string)
 * @returns Amount in usei as bigint
 */
export function seiToUsei(sei: number | string): bigint {
    if (typeof sei === 'string') {
        const parts = sei.split('.');
        const whole = BigInt(parts[0]) * USEI_PER_SEI;
        if (parts.length === 1) return whole;

        const decStr = parts[1].padEnd(6, '0').slice(0, 6);
        return whole + BigInt(decStr);
    }
    return seiToUsei(sei.toString());
}

/**
 * Convert usei to SEI string
 * @param usei Amount in usei
 * @returns Formatted SEI amount string (up to 6 decimals)
 */
export function useiToSei(usei: bigint): string {
    const whole = usei / USEI_PER_SEI;
    const remainder = usei % USEI_PER_SEI;

    if (remainder === 0n) return whole.toString();

    const fracStr = remainder.toString().padStart(6, '0').replace(/0+$/, '');
    return `${whole}.${fracStr}`;
}

/**
 * Format usei as human-readable string with units
 * @param usei Amount in usei
 * @returns e.g. "1.5 SEI" or "500,000 usei"
 */
export function formatSEIUsei(usei: bigint): string {
    if (usei >= USEI_PER_SEI) {
        return `${useiToSei(usei)} SEI`;
    }
    return `${usei.toLocaleString()} usei`;
}

// =============================================================================
// VALIDATION UTILITIES
// =============================================================================

/**
 * Validate a Sei EVM-compatible address (20-byte hex, 0x-prefixed)
 * @param address Sei address string
 * @returns True if the address format appears valid
 */
export function isValidSeiAddress(address: string): boolean {
    return /^0x[0-9a-fA-F]{40}$/.test(address);
}

/**
 * Validate a deposit amount is within bridge limits
 * @param amountUsei Amount in usei
 * @returns Object with valid flag and error message if invalid
 */
export function validateSEIDepositAmount(amountUsei: bigint): {
    valid: boolean;
    error?: string;
} {
    if (amountUsei < SEI_MIN_DEPOSIT_USEI) {
        return {
            valid: false,
            error: `Amount ${formatSEIUsei(amountUsei)} is below minimum deposit of ${formatSEIUsei(SEI_MIN_DEPOSIT_USEI)}`,
        };
    }
    if (amountUsei > SEI_MAX_DEPOSIT_USEI) {
        return {
            valid: false,
            error: `Amount ${formatSEIUsei(amountUsei)} exceeds maximum deposit of ${formatSEIUsei(SEI_MAX_DEPOSIT_USEI)}`,
        };
    }
    return { valid: true };
}

// =============================================================================
// FEE CALCULATIONS
// =============================================================================

/**
 * Calculate the bridge fee for a given amount
 * @param amountUsei Gross amount in usei
 * @returns Fee in usei (0.05% by default)
 */
export function calculateSeiBridgeFee(amountUsei: bigint): bigint {
    return (amountUsei * SEI_BRIDGE_FEE_BPS) / SEI_BPS_DENOMINATOR;
}

/**
 * Calculate the net amount after bridge fee
 * @param amountUsei Gross amount in usei
 * @returns Net amount in usei
 */
export function calculateSeiNetAmount(amountUsei: bigint): bigint {
    return amountUsei - calculateSeiBridgeFee(amountUsei);
}

// =============================================================================
// ESCROW UTILITIES
// =============================================================================

/**
 * Generate a random preimage for HTLC escrow
 * @returns 32-byte hex preimage
 */
export function generateSeiPreimage(): `0x${string}` {
    const bytes = new Uint8Array(32);
    crypto.getRandomValues(bytes);
    return `0x${Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('')}`;
}

/**
 * Compute the SHA-256 hashlock from a preimage
 * @param preimage The 32-byte hex preimage
 * @returns SHA-256 hash of the preimage
 */
export async function computeSeiHashlock(preimage: `0x${string}`): Promise<`0x${string}`> {
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
export function validateSeiEscrowTimelocks(
    finishAfter: number,
    cancelAfter: number
): { valid: boolean; error?: string } {
    const now = Math.floor(Date.now() / 1000);

    if (finishAfter <= now) {
        return { valid: false, error: 'finishAfter must be in the future' };
    }

    const duration = cancelAfter - finishAfter;

    if (duration < SEI_MIN_ESCROW_TIMELOCK) {
        return {
            valid: false,
            error: `Escrow duration ${duration}s is below minimum ${SEI_MIN_ESCROW_TIMELOCK}s (1 hour)`,
        };
    }

    if (duration > SEI_MAX_ESCROW_TIMELOCK) {
        return {
            valid: false,
            error: `Escrow duration ${duration}s exceeds maximum ${SEI_MAX_ESCROW_TIMELOCK}s (30 days)`,
        };
    }

    return { valid: true };
}

// =============================================================================
// TIMING UTILITIES
// =============================================================================

/**
 * Estimate block finalization time
 * @param confirmations Number of block confirmations (default: 8)
 * @returns Estimated time in milliseconds
 */
export function estimateSeiBlockFinalityMs(confirmations?: number): number {
    const n = confirmations ?? SEI_DEFAULT_BLOCK_CONFIRMATIONS;
    return n * SEI_BLOCK_TIME_MS;
}

/**
 * Check if a withdrawal is eligible for refund
 * @param initiatedAt Timestamp when withdrawal was initiated (UNIX seconds)
 * @returns True if the refund delay (36 hours) has passed
 */
export function isSeiRefundEligible(initiatedAt: number): boolean {
    const now = Math.floor(Date.now() / 1000);
    return now >= initiatedAt + SEI_WITHDRAWAL_REFUND_DELAY;
}

/**
 * Estimate time for a given number of Twin-Turbo consensus rounds
 * @param rounds Number of consensus rounds
 * @returns Estimated time in milliseconds
 */
export function estimateSeiConsensusTimeMs(rounds: number): number {
    return rounds * SEI_BLOCK_TIME_MS;
}

// =============================================================================
// ABI FRAGMENTS
// =============================================================================

export const SEI_BRIDGE_ABI = [
    // Configuration
    'function configure(address seiBridgeContract, address wrappedSEI, address validatorOracle, uint256 minValidatorSignatures, uint256 requiredBlockConfirmations) external',
    'function setTreasury(address _treasury) external',

    // Deposits (Sei → Soul)
    'function initiateSEIDeposit(bytes32 seiTxHash, bytes32 seiSender, address evmRecipient, uint256 amountUsei, uint256 blockHeight, (bytes32 leafHash, bytes32[] proof, uint256 index) txProof, (address validator, bytes signature)[] attestations) external returns (bytes32)',
    'function completeSEIDeposit(bytes32 depositId) external',

    // Withdrawals (Soul → Sei)
    'function initiateWithdrawal(bytes32 seiRecipient, uint256 amountUsei) external returns (bytes32)',
    'function completeWithdrawal(bytes32 withdrawalId, bytes32 seiTxHash, (bytes32 leafHash, bytes32[] proof, uint256 index) txProof, (address validator, bytes signature)[] attestations) external',
    'function refundWithdrawal(bytes32 withdrawalId) external',

    // Escrow (Atomic Swaps)
    'function createEscrow(bytes32 seiParty, bytes32 hashlock, uint256 finishAfter, uint256 cancelAfter) external payable returns (bytes32)',
    'function finishEscrow(bytes32 escrowId, bytes32 preimage) external',
    'function cancelEscrow(bytes32 escrowId) external',

    // Privacy
    'function registerPrivateDeposit(bytes32 depositId, bytes32 commitment, bytes32 nullifier, bytes zkProof) external',

    // Block Header Verification
    'function submitBlockHeader(uint256 height, bytes32 blockHash, bytes32 parentHash, bytes32 stateRoot, bytes32 txRoot, bytes32 validatorSetHash, uint256 timestamp, uint256 numTxs, (address validator, bytes signature)[] attestations) external',

    // Views
    'function getDeposit(bytes32 depositId) external view returns (tuple)',
    'function getWithdrawal(bytes32 withdrawalId) external view returns (tuple)',
    'function getEscrow(bytes32 escrowId) external view returns (tuple)',
    'function getBlockHeader(uint256 height) external view returns (tuple)',
    'function getUserDeposits(address user) external view returns (bytes32[])',
    'function getUserWithdrawals(address user) external view returns (bytes32[])',
    'function getUserEscrows(address user) external view returns (bytes32[])',
    'function getBridgeStats() external view returns (uint256, uint256, uint256, uint256, uint256, uint256, uint256)',

    // Admin
    'function pause() external',
    'function unpause() external',
    'function withdrawFees() external',

    // Constants
    'function SEI_CHAIN_ID() view returns (uint256)',
    'function USEI_PER_SEI() view returns (uint256)',
    'function MIN_DEPOSIT_USEI() view returns (uint256)',
    'function MAX_DEPOSIT_USEI() view returns (uint256)',
    'function BRIDGE_FEE_BPS() view returns (uint256)',
    'function WITHDRAWAL_REFUND_DELAY() view returns (uint256)',
    'function DEFAULT_BLOCK_CONFIRMATIONS() view returns (uint256)',

    // State
    'function depositNonce() view returns (uint256)',
    'function withdrawalNonce() view returns (uint256)',
    'function escrowNonce() view returns (uint256)',
    'function latestBlockHeight() view returns (uint256)',
    'function totalDeposited() view returns (uint256)',
    'function totalWithdrawn() view returns (uint256)',
    'function accumulatedFees() view returns (uint256)',
    'function treasury() view returns (address)',
    'function usedSeiTxHashes(bytes32) view returns (bool)',
    'function usedNullifiers(bytes32) view returns (bool)',

    // Events
    'event BridgeConfigured(address indexed seiBridgeContract, address wrappedSEI, address validatorOracle)',
    'event SEIDepositInitiated(bytes32 indexed depositId, bytes32 indexed seiTxHash, bytes32 seiSender, address indexed evmRecipient, uint256 amountUsei)',
    'event SEIDepositCompleted(bytes32 indexed depositId, address indexed evmRecipient, uint256 amountUsei)',
    'event SEIWithdrawalInitiated(bytes32 indexed withdrawalId, address indexed evmSender, bytes32 seiRecipient, uint256 amountUsei)',
    'event SEIWithdrawalCompleted(bytes32 indexed withdrawalId, bytes32 seiTxHash)',
    'event SEIWithdrawalRefunded(bytes32 indexed withdrawalId, address indexed evmSender, uint256 amountUsei)',
    'event EscrowCreated(bytes32 indexed escrowId, address indexed evmParty, bytes32 seiParty, uint256 amountUsei, bytes32 hashlock)',
    'event EscrowFinished(bytes32 indexed escrowId, bytes32 preimage)',
    'event EscrowCancelled(bytes32 indexed escrowId)',
    'event BlockHeaderVerified(uint256 indexed height, bytes32 blockHash, uint256 timestamp)',
    'event PrivateDepositRegistered(bytes32 indexed depositId, bytes32 commitment, bytes32 nullifier)',
    'event FeesWithdrawn(address indexed recipient, uint256 amount)',
] as const;

export const WRAPPED_SEI_ABI = [
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
