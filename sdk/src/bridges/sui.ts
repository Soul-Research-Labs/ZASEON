/**
 * Soul Protocol - Sui Bridge SDK Module
 *
 * TypeScript utilities and types for interacting with the SuiBridgeAdapter contract.
 * Provides Sui-specific helpers: MIST conversions, address validation,
 * fee calculations, checkpoint utilities, and escrow helpers.
 *
 * Sui is a Layer 1 blockchain by Mysten Labs using the Move programming language
 * and Mysticeti BFT consensus with sub-second finality (~400ms). It features an
 * object-centric data model with 9-decimal precision (MIST).
 *
 * @example
 * ```typescript
 * import { suiToMist, mistToSui, calculateSuiBridgeFee, SUI_BRIDGE_ABI } from './sui';
 *
 * const amount = suiToMist(10); // 10_000_000_000n (10 SUI in MIST)
 * const fee = calculateSuiBridgeFee(amount); // 6_000_000n (0.06%)
 * ```
 */

// =============================================================================
// CONSTANTS
// =============================================================================

/** 1 SUI = 1e9 MIST (9 decimals) */
export const MIST_PER_SUI = 1_000_000_000n;

/** Minimum deposit: 0.1 SUI (100,000,000 MIST) */
export const SUI_MIN_DEPOSIT_MIST = MIST_PER_SUI / 10n;

/** Maximum deposit: 10,000,000 SUI */
export const SUI_MAX_DEPOSIT_MIST = 10_000_000n * MIST_PER_SUI;

/** Bridge fee: 6 BPS (0.06%) */
export const SUI_BRIDGE_FEE_BPS = 6n;

/** BPS denominator */
export const SUI_BPS_DENOMINATOR = 10_000n;

/** Minimum escrow timelock: 1 hour */
export const SUI_MIN_ESCROW_TIMELOCK = 3600;

/** Maximum escrow timelock: 30 days */
export const SUI_MAX_ESCROW_TIMELOCK = 30 * 24 * 3600;

/** Withdrawal refund delay: 48 hours */
export const SUI_WITHDRAWAL_REFUND_DELAY = 48 * 3600;

/** Default checkpoint confirmations for finality */
export const SUI_DEFAULT_CHECKPOINT_CONFIRMATIONS = 10;

/** Sui block time in ms (~400ms Mysticeti consensus) */
export const SUI_BLOCK_TIME_MS = 400;

/** Sui chain ID (sui-mainnet EVM mapping) */
export const SUI_CHAIN_ID = 784;

/** Sui epoch duration (~24 hours) */
export const SUI_EPOCH_DURATION_MS = 24 * 60 * 60 * 1000;

// =============================================================================
// ENUMS
// =============================================================================

export enum SUIDepositStatus {
    PENDING = 0,
    VERIFIED = 1,
    COMPLETED = 2,
    FAILED = 3,
}

export enum SUIWithdrawalStatus {
    PENDING = 0,
    PROCESSING = 1,
    COMPLETED = 2,
    REFUNDED = 3,
    FAILED = 4,
}

export enum SUIEscrowStatus {
    ACTIVE = 0,
    FINISHED = 1,
    CANCELLED = 2,
}

export enum SuiBridgeOpType {
    TOKEN_TRANSFER = 0,
    OBJECT_TRANSFER = 1,
    COMMITTEE_UPDATE = 2,
    EMERGENCY_OP = 3,
}

// =============================================================================
// TYPES
// =============================================================================

export interface SUIDeposit {
    depositId: `0x${string}`;
    suiTxDigest: `0x${string}`;
    suiSender: `0x${string}`; // 32-byte Sui address
    evmRecipient: `0x${string}`;
    amountMist: bigint;
    netAmountMist: bigint;
    fee: bigint;
    status: SUIDepositStatus;
    checkpointSequence: bigint;
    initiatedAt: bigint;
    completedAt: bigint;
}

export interface SUIWithdrawal {
    withdrawalId: `0x${string}`;
    evmSender: `0x${string}`;
    suiRecipient: `0x${string}`; // 32-byte Sui address
    amountMist: bigint;
    suiTxDigest: `0x${string}`;
    status: SUIWithdrawalStatus;
    initiatedAt: bigint;
    completedAt: bigint;
}

export interface SUIEscrow {
    escrowId: `0x${string}`;
    evmParty: `0x${string}`;
    suiParty: `0x${string}`; // 32-byte Sui address
    amountMist: bigint;
    hashlock: `0x${string}`;
    preimage: `0x${string}`;
    finishAfter: bigint;
    cancelAfter: bigint;
    status: SUIEscrowStatus;
    createdAt: bigint;
}

export interface SuiBridgeConfig {
    suiBridgeContract: `0x${string}`;
    wrappedSUI: `0x${string}`;
    validatorCommitteeOracle: `0x${string}`;
    minCommitteeSignatures: bigint;
    requiredCheckpointConfirmations: bigint;
    active: boolean;
}

export interface SuiCheckpoint {
    sequenceNumber: bigint;
    digest: `0x${string}`;
    previousDigest: `0x${string}`;
    transactionDigestRoot: `0x${string}`;
    effectsRoot: `0x${string}`;
    epoch: bigint;
    validatorSetHash: `0x${string}`;
    timestampMs: bigint;
    verified: boolean;
}

export interface ValidatorAttestation {
    validatorPublicKey: `0x${string}`; // BLS12-381 compressed public key hash
    signature: `0x${string}`;
}

export interface SuiObjectProof {
    objectId: `0x${string}`;
    version: bigint;
    objectDigest: `0x${string}`;
    proof: `0x${string}`[];
    proofIndex: bigint;
}

export interface SuiBridgeStats {
    totalDeposited: bigint;
    totalWithdrawn: bigint;
    totalEscrows: bigint;
    totalEscrowsFinished: bigint;
    totalEscrowsCancelled: bigint;
    accumulatedFees: bigint;
    latestCheckpointSequence: bigint;
}

// =============================================================================
// CONVERSION UTILITIES
// =============================================================================

/**
 * Convert SUI to MIST (smallest unit)
 * @param sui Amount in SUI (supports decimals as string)
 * @returns Amount in MIST as bigint
 */
export function suiToMist(sui: number | string): bigint {
    if (typeof sui === 'string') {
        const parts = sui.split('.');
        const whole = BigInt(parts[0]) * MIST_PER_SUI;
        if (parts.length === 1) return whole;

        const decStr = parts[1].padEnd(9, '0').slice(0, 9);
        return whole + BigInt(decStr);
    }
    return suiToMist(sui.toString());
}

/**
 * Convert MIST to SUI string
 * @param mist Amount in MIST
 * @returns Formatted SUI amount string (up to 9 decimals)
 */
export function mistToSui(mist: bigint): string {
    const whole = mist / MIST_PER_SUI;
    const remainder = mist % MIST_PER_SUI;

    if (remainder === 0n) return whole.toString();

    const fracStr = remainder.toString().padStart(9, '0').replace(/0+$/, '');
    return `${whole}.${fracStr}`;
}

/**
 * Format MIST as human-readable string with units
 * @param mist Amount in MIST
 * @returns e.g. "1.5 SUI" or "500,000 MIST"
 */
export function formatSUIMist(mist: bigint): string {
    if (mist >= MIST_PER_SUI) {
        return `${mistToSui(mist)} SUI`;
    }
    return `${mist.toLocaleString()} MIST`;
}

// =============================================================================
// VALIDATION UTILITIES
// =============================================================================

/**
 * Validate a Sui address (32-byte hex, 0x-prefixed, 64 hex chars)
 * @param address Sui address string
 * @returns True if the address format appears valid
 */
export function isValidSuiAddress(address: string): boolean {
    return /^0x[0-9a-fA-F]{64}$/.test(address);
}

/**
 * Validate a deposit amount is within bridge limits
 * @param amountMist Amount in MIST
 * @returns Object with valid flag and error message if invalid
 */
export function validateSUIDepositAmount(amountMist: bigint): {
    valid: boolean;
    error?: string;
} {
    if (amountMist < SUI_MIN_DEPOSIT_MIST) {
        return {
            valid: false,
            error: `Amount ${formatSUIMist(amountMist)} is below minimum deposit of ${formatSUIMist(SUI_MIN_DEPOSIT_MIST)}`,
        };
    }
    if (amountMist > SUI_MAX_DEPOSIT_MIST) {
        return {
            valid: false,
            error: `Amount ${formatSUIMist(amountMist)} exceeds maximum deposit of ${formatSUIMist(SUI_MAX_DEPOSIT_MIST)}`,
        };
    }
    return { valid: true };
}

// =============================================================================
// FEE CALCULATIONS
// =============================================================================

/**
 * Calculate the bridge fee for a given amount
 * @param amountMist Gross amount in MIST
 * @returns Fee in MIST (0.06% by default)
 */
export function calculateSuiBridgeFee(amountMist: bigint): bigint {
    return (amountMist * SUI_BRIDGE_FEE_BPS) / SUI_BPS_DENOMINATOR;
}

/**
 * Calculate the net amount after bridge fee
 * @param amountMist Gross amount in MIST
 * @returns Net amount in MIST
 */
export function calculateSuiNetAmount(amountMist: bigint): bigint {
    return amountMist - calculateSuiBridgeFee(amountMist);
}

// =============================================================================
// ESCROW UTILITIES
// =============================================================================

/**
 * Generate a random preimage for HTLC escrow
 * @returns 32-byte hex preimage
 */
export function generateSuiPreimage(): `0x${string}` {
    const bytes = new Uint8Array(32);
    crypto.getRandomValues(bytes);
    return `0x${Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('')}`;
}

/**
 * Compute the SHA-256 hashlock from a preimage
 * @param preimage The 32-byte hex preimage
 * @returns SHA-256 hash of the preimage
 */
export async function computeSuiHashlock(preimage: `0x${string}`): Promise<`0x${string}`> {
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
export function validateSuiEscrowTimelocks(
    finishAfter: number,
    cancelAfter: number
): { valid: boolean; error?: string } {
    const now = Math.floor(Date.now() / 1000);

    if (finishAfter <= now) {
        return { valid: false, error: 'finishAfter must be in the future' };
    }

    const duration = cancelAfter - finishAfter;

    if (duration < SUI_MIN_ESCROW_TIMELOCK) {
        return {
            valid: false,
            error: `Escrow duration ${duration}s is below minimum ${SUI_MIN_ESCROW_TIMELOCK}s (1 hour)`,
        };
    }

    if (duration > SUI_MAX_ESCROW_TIMELOCK) {
        return {
            valid: false,
            error: `Escrow duration ${duration}s exceeds maximum ${SUI_MAX_ESCROW_TIMELOCK}s (30 days)`,
        };
    }

    return { valid: true };
}

// =============================================================================
// TIMING UTILITIES
// =============================================================================

/**
 * Estimate checkpoint finalization time
 * @param confirmations Number of checkpoint confirmations (default: 10)
 * @returns Estimated time in milliseconds
 */
export function estimateSuiCheckpointFinalityMs(confirmations?: number): number {
    const n = confirmations ?? SUI_DEFAULT_CHECKPOINT_CONFIRMATIONS;
    return n * SUI_BLOCK_TIME_MS;
}

/**
 * Check if a withdrawal is eligible for refund
 * @param initiatedAt Timestamp when withdrawal was initiated (UNIX seconds)
 * @returns True if the refund delay (48 hours) has passed
 */
export function isSuiRefundEligible(initiatedAt: number): boolean {
    const now = Math.floor(Date.now() / 1000);
    return now >= initiatedAt + SUI_WITHDRAWAL_REFUND_DELAY;
}

/**
 * Estimate remaining time until epoch change
 * @param epochStartMs Epoch start time in milliseconds
 * @returns Remaining time in milliseconds (0 if epoch should have ended)
 */
export function estimateRemainingEpochMs(epochStartMs: number): number {
    const now = Date.now();
    const epochEnd = epochStartMs + SUI_EPOCH_DURATION_MS;
    return Math.max(0, epochEnd - now);
}

/**
 * Estimate time for a given number of Mysticeti consensus rounds
 * @param rounds Number of consensus rounds
 * @returns Estimated time in milliseconds
 */
export function estimateSuiConsensusTimeMs(rounds: number): number {
    return rounds * SUI_BLOCK_TIME_MS;
}

// =============================================================================
// ABI FRAGMENTS
// =============================================================================

export const SUI_BRIDGE_ABI = [
    // Configuration
    'function configure(address suiBridgeContract, address wrappedSUI, address validatorCommitteeOracle, uint256 minCommitteeSignatures, uint256 requiredCheckpointConfirmations) external',
    'function setTreasury(address _treasury) external',

    // Deposits (Sui → Soul)
    'function initiateSUIDeposit(bytes32 suiTxDigest, bytes32 suiSender, address evmRecipient, uint256 amountMist, uint256 checkpointSequence, (bytes32 objectId, uint256 version, bytes32 objectDigest, bytes32[] proof, uint256 proofIndex) txProof, (bytes32 validatorPublicKey, bytes signature)[] attestations) external returns (bytes32)',
    'function completeSUIDeposit(bytes32 depositId) external',

    // Withdrawals (Soul → Sui)
    'function initiateWithdrawal(bytes32 suiRecipient, uint256 amountMist) external returns (bytes32)',
    'function completeWithdrawal(bytes32 withdrawalId, bytes32 suiTxDigest, (bytes32 objectId, uint256 version, bytes32 objectDigest, bytes32[] proof, uint256 proofIndex) txProof, (bytes32 validatorPublicKey, bytes signature)[] attestations) external',
    'function refundWithdrawal(bytes32 withdrawalId) external',

    // Escrow (Atomic Swaps)
    'function createEscrow(bytes32 suiParty, bytes32 hashlock, uint256 finishAfter, uint256 cancelAfter) external payable returns (bytes32)',
    'function finishEscrow(bytes32 escrowId, bytes32 preimage) external',
    'function cancelEscrow(bytes32 escrowId) external',

    // Privacy
    'function registerPrivateDeposit(bytes32 depositId, bytes32 commitment, bytes32 nullifier, bytes zkProof) external',

    // Checkpoint Verification
    'function submitCheckpoint(uint256 sequenceNumber, bytes32 digest, bytes32 previousDigest, bytes32 transactionDigestRoot, bytes32 effectsRoot, uint256 epoch, bytes32 validatorSetHash, uint256 timestampMs, (bytes32 validatorPublicKey, bytes signature)[] attestations) external',

    // Views
    'function getDeposit(bytes32 depositId) external view returns (tuple)',
    'function getWithdrawal(bytes32 withdrawalId) external view returns (tuple)',
    'function getEscrow(bytes32 escrowId) external view returns (tuple)',
    'function getCheckpoint(uint256 sequenceNumber) external view returns (tuple)',
    'function getUserDeposits(address user) external view returns (bytes32[])',
    'function getUserWithdrawals(address user) external view returns (bytes32[])',
    'function getUserEscrows(address user) external view returns (bytes32[])',
    'function getBridgeStats() external view returns (uint256, uint256, uint256, uint256, uint256, uint256, uint256)',

    // Admin
    'function pause() external',
    'function unpause() external',
    'function withdrawFees() external',

    // Constants
    'function SUI_CHAIN_ID() view returns (uint256)',
    'function MIST_PER_SUI() view returns (uint256)',
    'function MIN_DEPOSIT_MIST() view returns (uint256)',
    'function MAX_DEPOSIT_MIST() view returns (uint256)',
    'function BRIDGE_FEE_BPS() view returns (uint256)',
    'function WITHDRAWAL_REFUND_DELAY() view returns (uint256)',
    'function DEFAULT_CHECKPOINT_CONFIRMATIONS() view returns (uint256)',

    // State
    'function depositNonce() view returns (uint256)',
    'function withdrawalNonce() view returns (uint256)',
    'function escrowNonce() view returns (uint256)',
    'function latestCheckpointSequence() view returns (uint256)',
    'function currentEpoch() view returns (uint256)',
    'function totalDeposited() view returns (uint256)',
    'function totalWithdrawn() view returns (uint256)',
    'function accumulatedFees() view returns (uint256)',
    'function treasury() view returns (address)',
    'function usedSuiTxDigests(bytes32) view returns (bool)',
    'function usedNullifiers(bytes32) view returns (bool)',

    // Events
    'event BridgeConfigured(address indexed suiBridgeContract, address wrappedSUI, address validatorCommitteeOracle)',
    'event SUIDepositInitiated(bytes32 indexed depositId, bytes32 indexed suiTxDigest, bytes32 suiSender, address indexed evmRecipient, uint256 amountMist)',
    'event SUIDepositCompleted(bytes32 indexed depositId, address indexed evmRecipient, uint256 amountMist)',
    'event SUIWithdrawalInitiated(bytes32 indexed withdrawalId, address indexed evmSender, bytes32 suiRecipient, uint256 amountMist)',
    'event SUIWithdrawalCompleted(bytes32 indexed withdrawalId, bytes32 suiTxDigest)',
    'event SUIWithdrawalRefunded(bytes32 indexed withdrawalId, address indexed evmSender, uint256 amountMist)',
    'event EscrowCreated(bytes32 indexed escrowId, address indexed evmParty, bytes32 suiParty, uint256 amountMist, bytes32 hashlock)',
    'event EscrowFinished(bytes32 indexed escrowId, bytes32 preimage)',
    'event EscrowCancelled(bytes32 indexed escrowId)',
    'event CheckpointVerified(uint256 indexed sequenceNumber, bytes32 digest, uint256 epoch)',
    'event PrivateDepositRegistered(bytes32 indexed depositId, bytes32 commitment, bytes32 nullifier)',
    'event FeesWithdrawn(address indexed recipient, uint256 amount)',
] as const;

export const WRAPPED_SUI_ABI = [
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
