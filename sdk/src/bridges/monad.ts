/**
 * Soul Protocol - Monad Bridge SDK Module
 *
 * TypeScript utilities and types for interacting with the MonadBridgeAdapter contract.
 * Provides Monad-specific helpers: wei conversions, address validation,
 * fee calculations, MonadBFT block proof utilities, and escrow helpers.
 *
 * Monad is an EVM-compatible Layer 1 using MonadBFT (pipelined HotStuff-2) consensus
 * with optimistic parallel execution via MonadDb. It features ~1s block times,
 * deferred execution for throughput optimization, single-slot finality via BFT,
 * and 18-decimal precision (wei) for its native MON token.
 *
 * @example
 * ```typescript
 * import { monToWei, weiToMon, calculateMonadBridgeFee, MONAD_BRIDGE_ABI } from './monad';
 *
 * const amount = monToWei(10); // 10_000_000_000_000_000_000n (10 MON in wei)
 * const fee = calculateMonadBridgeFee(amount); // 3_000_000_000_000_000n (0.03%)
 * ```
 */

// =============================================================================
// CONSTANTS
// =============================================================================

/** 1 MON = 1e18 wei (18 decimals) */
export const WEI_PER_MON = 10n ** 18n;

/** Minimum deposit: 0.01 MON (1e16 wei) */
export const MON_MIN_DEPOSIT_WEI = 10n ** 16n;

/** Maximum deposit: 10,000,000 MON */
export const MON_MAX_DEPOSIT_WEI = 10_000_000n * WEI_PER_MON;

/** Bridge fee: 3 BPS (0.03%) */
export const MON_BRIDGE_FEE_BPS = 3n;

/** BPS denominator */
export const MON_BPS_DENOMINATOR = 10_000n;

/** Minimum escrow timelock: 1 hour */
export const MON_MIN_ESCROW_TIMELOCK = 3600;

/** Maximum escrow timelock: 30 days */
export const MON_MAX_ESCROW_TIMELOCK = 30 * 24 * 3600;

/** Withdrawal refund delay: 24 hours */
export const MON_WITHDRAWAL_REFUND_DELAY = 24 * 3600;

/** Default block confirmations for finality */
export const MON_DEFAULT_BLOCK_CONFIRMATIONS = 1;

/** Monad block time in ms (~1s MonadBFT/HotStuff-2 consensus) */
export const MON_BLOCK_TIME_MS = 1000;

/** Monad mainnet chain ID */
export const MONAD_CHAIN_ID = 41454;

/** Monad epoch duration (~4 hours) */
export const MONAD_EPOCH_DURATION_MS = 4 * 60 * 60 * 1000;

// =============================================================================
// ENUMS
// =============================================================================

export enum MONDepositStatus {
    PENDING = 0,
    VERIFIED = 1,
    COMPLETED = 2,
    FAILED = 3,
}

export enum MONWithdrawalStatus {
    PENDING = 0,
    PROCESSING = 1,
    COMPLETED = 2,
    REFUNDED = 3,
    FAILED = 4,
}

export enum MONEscrowStatus {
    ACTIVE = 0,
    FINISHED = 1,
    CANCELLED = 2,
}

export enum MonadBridgeOpType {
    MON_TRANSFER = 0,
    ERC20_TRANSFER = 1,
    VALIDATOR_UPDATE = 2,
    EMERGENCY_OP = 3,
}

// =============================================================================
// TYPES
// =============================================================================

export interface MONDeposit {
    depositId: `0x${string}`;
    monadTxHash: `0x${string}`;
    monadSender: `0x${string}`;
    evmRecipient: `0x${string}`;
    amountWei: bigint;
    netAmountWei: bigint;
    fee: bigint;
    status: MONDepositStatus;
    blockNumber: bigint;
    initiatedAt: bigint;
    completedAt: bigint;
}

export interface MONWithdrawal {
    withdrawalId: `0x${string}`;
    evmSender: `0x${string}`;
    monadRecipient: `0x${string}`;
    amountWei: bigint;
    monadTxHash: `0x${string}`;
    status: MONWithdrawalStatus;
    initiatedAt: bigint;
    completedAt: bigint;
}

export interface MONEscrow {
    escrowId: `0x${string}`;
    evmParty: `0x${string}`;
    monadParty: `0x${string}`;
    amountWei: bigint;
    hashlock: `0x${string}`;
    preimage: `0x${string}`;
    finishAfter: bigint;
    cancelAfter: bigint;
    status: MONEscrowStatus;
    createdAt: bigint;
}

export interface MonadBridgeConfig {
    monadBridgeContract: `0x${string}`;
    wrappedMON: `0x${string}`;
    validatorOracle: `0x${string}`;
    minValidatorSignatures: bigint;
    requiredBlockConfirmations: bigint;
    active: boolean;
}

export interface MonadBFTBlock {
    blockNumber: bigint;
    blockHash: `0x${string}`;
    parentHash: `0x${string}`;
    stateRoot: `0x${string}`;
    executionRoot: `0x${string}`;
    round: bigint;
    timestamp: bigint;
    verified: boolean;
}

export interface MonadStateProof {
    merkleProof: `0x${string}`[];
    blockIndex: bigint;
    leafHash: `0x${string}`;
}

export interface ValidatorAttestation {
    validator: `0x${string}`;
    signature: `0x${string}`;
}

export interface MonadBridgeStats {
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
 * Convert MON to wei (smallest unit)
 * @param mon Amount in MON (supports decimals as string)
 * @returns Amount in wei as bigint
 */
export function monToWei(mon: number | string): bigint {
    if (typeof mon === 'string') {
        const parts = mon.split('.');
        const whole = BigInt(parts[0]) * WEI_PER_MON;
        if (parts.length === 1) return whole;

        const decStr = parts[1].padEnd(18, '0').slice(0, 18);
        return whole + BigInt(decStr);
    }
    return monToWei(mon.toString());
}

/**
 * Convert wei to MON string
 * @param wei Amount in wei
 * @returns Formatted MON amount string (up to 18 decimals)
 */
export function weiToMon(wei: bigint): string {
    const whole = wei / WEI_PER_MON;
    const remainder = wei % WEI_PER_MON;

    if (remainder === 0n) return whole.toString();

    const fracStr = remainder.toString().padStart(18, '0').replace(/0+$/, '');
    return `${whole}.${fracStr}`;
}

/**
 * Format wei as human-readable string with units
 * @param wei Amount in wei
 * @returns e.g. "1.5 MON" or "500,000 wei"
 */
export function formatMONWei(wei: bigint): string {
    if (wei >= WEI_PER_MON) {
        return `${weiToMon(wei)} MON`;
    }
    return `${wei.toLocaleString()} wei`;
}

// =============================================================================
// VALIDATION UTILITIES
// =============================================================================

/**
 * Validate a Monad address (20-byte hex, 0x-prefixed, 40 hex chars)
 * @param address Monad address string
 * @returns True if the address format appears valid
 */
export function isValidMonadAddress(address: string): boolean {
    return /^0x[0-9a-fA-F]{40}$/.test(address);
}

/**
 * Validate a deposit amount is within bridge limits
 * @param amountWei Amount in wei
 * @returns Object with valid flag and error message if invalid
 */
export function validateMONDepositAmount(amountWei: bigint): {
    valid: boolean;
    error?: string;
} {
    if (amountWei < MON_MIN_DEPOSIT_WEI) {
        return {
            valid: false,
            error: `Amount ${formatMONWei(amountWei)} is below minimum deposit of ${formatMONWei(MON_MIN_DEPOSIT_WEI)}`,
        };
    }
    if (amountWei > MON_MAX_DEPOSIT_WEI) {
        return {
            valid: false,
            error: `Amount ${formatMONWei(amountWei)} exceeds maximum deposit of ${formatMONWei(MON_MAX_DEPOSIT_WEI)}`,
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
 * @returns Fee in wei (0.03% by default)
 */
export function calculateMonadBridgeFee(amountWei: bigint): bigint {
    return (amountWei * MON_BRIDGE_FEE_BPS) / MON_BPS_DENOMINATOR;
}

/**
 * Calculate the net amount after bridge fee
 * @param amountWei Gross amount in wei
 * @returns Net amount in wei
 */
export function calculateMonadNetAmount(amountWei: bigint): bigint {
    return amountWei - calculateMonadBridgeFee(amountWei);
}

// =============================================================================
// ESCROW UTILITIES
// =============================================================================

/**
 * Generate a random preimage for HTLC escrow
 * @returns 32-byte hex preimage
 */
export function generateMonadPreimage(): `0x${string}` {
    const bytes = new Uint8Array(32);
    crypto.getRandomValues(bytes);
    return `0x${Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('')}`;
}

/**
 * Compute the SHA-256 hashlock from a preimage
 * @param preimage The 32-byte hex preimage
 * @returns SHA-256 hash of the preimage
 */
export async function computeMonadHashlock(preimage: `0x${string}`): Promise<`0x${string}`> {
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
export function validateMonadEscrowTimelocks(
    finishAfter: number,
    cancelAfter: number
): { valid: boolean; error?: string } {
    const now = Math.floor(Date.now() / 1000);

    if (finishAfter <= now) {
        return { valid: false, error: 'finishAfter must be in the future' };
    }

    const duration = cancelAfter - finishAfter;

    if (duration < MON_MIN_ESCROW_TIMELOCK) {
        return {
            valid: false,
            error: `Escrow duration ${duration}s is below minimum ${MON_MIN_ESCROW_TIMELOCK}s (1 hour)`,
        };
    }

    if (duration > MON_MAX_ESCROW_TIMELOCK) {
        return {
            valid: false,
            error: `Escrow duration ${duration}s exceeds maximum ${MON_MAX_ESCROW_TIMELOCK}s (30 days)`,
        };
    }

    return { valid: true };
}

// =============================================================================
// TIMING UTILITIES
// =============================================================================

/**
 * Estimate block finalization time on Monad
 * @param confirmations Number of block confirmations (default: 1)
 * @returns Estimated time in milliseconds
 */
export function estimateMonadBlockFinalityMs(confirmations?: number): number {
    const n = confirmations ?? MON_DEFAULT_BLOCK_CONFIRMATIONS;
    return n * MON_BLOCK_TIME_MS;
}

/**
 * Check if a withdrawal is eligible for refund
 * @param initiatedAt Timestamp when withdrawal was initiated (UNIX seconds)
 * @returns True if the refund delay (24 hours) has passed
 */
export function isMonadRefundEligible(initiatedAt: number): boolean {
    const now = Math.floor(Date.now() / 1000);
    return now >= initiatedAt + MON_WITHDRAWAL_REFUND_DELAY;
}

/**
 * Estimate remaining time until epoch change
 * @param epochStartMs Epoch start time in milliseconds
 * @returns Remaining time in milliseconds (0 if epoch should have ended)
 */
export function estimateRemainingEpochMs(epochStartMs: number): number {
    const now = Date.now();
    const epochEnd = epochStartMs + MONAD_EPOCH_DURATION_MS;
    return Math.max(0, epochEnd - now);
}

/**
 * Estimate time for a given number of MonadBFT consensus rounds
 * @param rounds Number of consensus rounds
 * @returns Estimated time in milliseconds
 */
export function estimateMonadConsensusTimeMs(rounds: number): number {
    return rounds * MON_BLOCK_TIME_MS;
}

// =============================================================================
// ABI FRAGMENTS
// =============================================================================

export const MONAD_BRIDGE_ABI = [
    // Configuration
    'function configure(address monadBridgeContract, address wrappedMON, address validatorOracle, uint256 minValidatorSignatures, uint256 requiredBlockConfirmations) external',
    'function setTreasury(address _treasury) external',

    // Deposits (Monad → Soul)
    'function initiateMONDeposit(bytes32 monadTxHash, address monadSender, address evmRecipient, uint256 amountWei, uint256 blockNumber, (bytes32[] merkleProof, uint256 blockIndex, bytes32 leafHash) txProof, (address validator, bytes signature)[] attestations) external returns (bytes32)',
    'function completeMONDeposit(bytes32 depositId) external',

    // Withdrawals (Soul → Monad)
    'function initiateWithdrawal(address monadRecipient, uint256 amountWei) external returns (bytes32)',
    'function completeWithdrawal(bytes32 withdrawalId, bytes32 monadTxHash, (bytes32[] merkleProof, uint256 blockIndex, bytes32 leafHash) txProof, (address validator, bytes signature)[] attestations) external',
    'function refundWithdrawal(bytes32 withdrawalId) external',

    // Escrow (Atomic Swaps)
    'function createEscrow(address monadParty, bytes32 hashlock, uint256 finishAfter, uint256 cancelAfter) external payable returns (bytes32)',
    'function finishEscrow(bytes32 escrowId, bytes32 preimage) external',
    'function cancelEscrow(bytes32 escrowId) external',

    // Privacy
    'function registerPrivateDeposit(bytes32 depositId, bytes32 commitment, bytes32 nullifier, bytes zkProof) external',

    // MonadBFT Block Verification
    'function submitMonadBFTBlock(uint256 blockNumber, bytes32 blockHash, bytes32 parentHash, bytes32 stateRoot, bytes32 executionRoot, uint256 round, uint256 timestamp, (address validator, bytes signature)[] attestations) external',

    // Views
    'function getDeposit(bytes32 depositId) external view returns (tuple)',
    'function getWithdrawal(bytes32 withdrawalId) external view returns (tuple)',
    'function getEscrow(bytes32 escrowId) external view returns (tuple)',
    'function getMonadBFTBlock(uint256 blockNumber) external view returns (tuple)',
    'function getUserDeposits(address user) external view returns (bytes32[])',
    'function getUserWithdrawals(address user) external view returns (bytes32[])',
    'function getUserEscrows(address user) external view returns (bytes32[])',
    'function getBridgeStats() external view returns (uint256, uint256, uint256, uint256, uint256, uint256, uint256)',

    // Admin
    'function pause() external',
    'function unpause() external',
    'function withdrawFees() external',

    // Constants
    'function MONAD_CHAIN_ID() view returns (uint256)',
    'function WEI_PER_MON() view returns (uint256)',
    'function MIN_DEPOSIT_WEI() view returns (uint256)',
    'function MAX_DEPOSIT_WEI() view returns (uint256)',
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
    'function usedMonadTxHashes(bytes32) view returns (bool)',
    'function usedNullifiers(bytes32) view returns (bool)',

    // Events
    'event BridgeConfigured(address indexed monadBridgeContract, address wrappedMON, address validatorOracle)',
    'event MONDepositInitiated(bytes32 indexed depositId, bytes32 indexed monadTxHash, address monadSender, address indexed evmRecipient, uint256 amountWei)',
    'event MONDepositCompleted(bytes32 indexed depositId, address indexed evmRecipient, uint256 amountWei)',
    'event MONWithdrawalInitiated(bytes32 indexed withdrawalId, address indexed evmSender, address monadRecipient, uint256 amountWei)',
    'event MONWithdrawalCompleted(bytes32 indexed withdrawalId, bytes32 monadTxHash)',
    'event MONWithdrawalRefunded(bytes32 indexed withdrawalId, address indexed evmSender, uint256 amountWei)',
    'event EscrowCreated(bytes32 indexed escrowId, address indexed evmParty, address monadParty, uint256 amountWei, bytes32 hashlock)',
    'event EscrowFinished(bytes32 indexed escrowId, bytes32 preimage)',
    'event EscrowCancelled(bytes32 indexed escrowId)',
    'event MonadBFTBlockVerified(uint256 indexed blockNumber, bytes32 blockHash, bytes32 stateRoot)',
    'event PrivateDepositRegistered(bytes32 indexed depositId, bytes32 commitment, bytes32 nullifier)',
    'event FeesWithdrawn(address indexed recipient, uint256 amount)',
] as const;

export const WRAPPED_MON_ABI = [
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
