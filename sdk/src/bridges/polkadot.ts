/**
 * Soul Protocol - Polkadot Bridge SDK Module
 *
 * TypeScript utilities and types for interacting with the PolkadotBridgeAdapter contract.
 * Provides Polkadot-specific helpers: Planck conversions, address validation,
 * fee calculations, GRANDPA header utilities, and escrow helpers.
 *
 * Polkadot is a Layer 0 heterogeneous multi-chain protocol designed by Parity Technologies.
 * It uses GRANDPA (GHOST-based Recursive ANcestor Deriving Prefix Agreement) and BABE
 * consensus with ~6s block time on the relay chain. State proofs leverage Patricia-Merkle
 * tries, and addresses are SS58-encoded 32-byte public keys with 10-decimal precision (Planck).
 *
 * @example
 * ```typescript
 * import { dotToPlanck, planckToDot, calculatePolkadotBridgeFee, POLKADOT_BRIDGE_ABI } from './polkadot';
 *
 * const amount = dotToPlanck(10); // 100_000_000_000n (10 DOT in Planck)
 * const fee = calculatePolkadotBridgeFee(amount); // 60_000_000n (0.06%)
 * ```
 */

// =============================================================================
// CONSTANTS
// =============================================================================

/** 1 DOT = 1e10 Planck (10 decimals) */
export const PLANCK_PER_DOT = 10_000_000_000n;

/** Minimum deposit: 0.1 DOT (1,000,000,000 Planck) */
export const MIN_DEPOSIT_PLANCK = PLANCK_PER_DOT / 10n;

/** Maximum deposit: 10,000,000 DOT */
export const MAX_DEPOSIT_PLANCK = 10_000_000n * PLANCK_PER_DOT;

/** Bridge fee: 6 BPS (0.06%) */
export const DOT_BRIDGE_FEE_BPS = 6n;

/** BPS denominator */
export const DOT_BPS_DENOMINATOR = 10_000n;

/** Minimum escrow timelock: 1 hour */
export const DOT_MIN_ESCROW_TIMELOCK = 3600;

/** Maximum escrow timelock: 30 days */
export const DOT_MAX_ESCROW_TIMELOCK = 30 * 24 * 3600;

/** Withdrawal refund delay: 24 hours */
export const DOT_WITHDRAWAL_REFUND_DELAY = 24 * 3600;

/** Default finality confirmations for GRANDPA */
export const DEFAULT_FINALITY_CONFIRMATIONS = 2;

/** Polkadot relay chain block time in ms (~6000ms) */
export const DOT_BLOCK_TIME_MS = 6000;

/** Polkadot relay chain ID (0 for relay chain) */
export const POLKADOT_CHAIN_ID = 0;

/** Polkadot epoch duration (~4 hours) */
export const POLKADOT_EPOCH_DURATION_MS = 4 * 60 * 60 * 1000;

// =============================================================================
// ENUMS
// =============================================================================

export enum DOTDepositStatus {
    PENDING = 0,
    VERIFIED = 1,
    COMPLETED = 2,
    FAILED = 3,
}

export enum DOTWithdrawalStatus {
    PENDING = 0,
    PROCESSING = 1,
    COMPLETED = 2,
    REFUNDED = 3,
    FAILED = 4,
}

export enum DOTEscrowStatus {
    ACTIVE = 0,
    FINISHED = 1,
    CANCELLED = 2,
}

export enum PolkadotBridgeOpType {
    BALANCE_TRANSFER = 0,
    XCM_TRANSFER = 1,
    VALIDATOR_SET_UPDATE = 2,
    EMERGENCY_OP = 3,
}

// =============================================================================
// TYPES
// =============================================================================

export interface DOTDeposit {
    depositId: `0x${string}`;
    substrateBlockHash: `0x${string}`;
    substrateSender: `0x${string}`; // 32-byte SS58-encoded address
    evmRecipient: `0x${string}`;
    amountPlanck: bigint;
    netAmountPlanck: bigint;
    fee: bigint;
    status: DOTDepositStatus;
    blockNumber: bigint;
    initiatedAt: bigint;
    completedAt: bigint;
}

export interface DOTWithdrawal {
    withdrawalId: `0x${string}`;
    evmSender: `0x${string}`;
    substrateRecipient: `0x${string}`; // 32-byte SS58-encoded address
    amountPlanck: bigint;
    substrateTxHash: `0x${string}`;
    status: DOTWithdrawalStatus;
    initiatedAt: bigint;
    completedAt: bigint;
}

export interface DOTEscrow {
    escrowId: `0x${string}`;
    evmParty: `0x${string}`;
    substrateParty: `0x${string}`; // 32-byte SS58-encoded address
    amountPlanck: bigint;
    hashlock: `0x${string}`;
    preimage: `0x${string}`;
    finishAfter: bigint;
    cancelAfter: bigint;
    status: DOTEscrowStatus;
    createdAt: bigint;
}

export interface PolkadotBridgeConfig {
    polkadotBridgeContract: `0x${string}`;
    wrappedDOT: `0x${string}`;
    validatorOracle: `0x${string}`;
    minValidatorSignatures: bigint;
    requiredFinalityConfirmations: bigint;
    active: boolean;
}

export interface GrandpaHeader {
    blockNumber: bigint;
    blockHash: `0x${string}`;
    parentHash: `0x${string}`;
    stateRoot: `0x${string}`;
    extrinsicsRoot: `0x${string}`;
    setId: bigint;
    timestamp: bigint;
    verified: boolean;
}

export interface SubstrateStateProof {
    trieNodes: `0x${string}`[];
    key: `0x${string}`;
    value: `0x${string}`;
    stateRoot: `0x${string}`;
}

export interface ValidatorAttestation {
    validator: `0x${string}`; // EVM-mapped validator address
    signature: `0x${string}`;
}

export interface PolkadotBridgeStats {
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
 * Convert DOT to Planck (smallest unit)
 * @param dot Amount in DOT (supports decimals as string)
 * @returns Amount in Planck as bigint
 */
export function dotToPlanck(dot: number | string): bigint {
    if (typeof dot === 'string') {
        const parts = dot.split('.');
        const whole = BigInt(parts[0]) * PLANCK_PER_DOT;
        if (parts.length === 1) return whole;

        const decStr = parts[1].padEnd(10, '0').slice(0, 10);
        return whole + BigInt(decStr);
    }
    return dotToPlanck(dot.toString());
}

/**
 * Convert Planck to DOT string
 * @param planck Amount in Planck
 * @returns Formatted DOT amount string (up to 10 decimals)
 */
export function planckToDot(planck: bigint): string {
    const whole = planck / PLANCK_PER_DOT;
    const remainder = planck % PLANCK_PER_DOT;

    if (remainder === 0n) return whole.toString();

    const fracStr = remainder.toString().padStart(10, '0').replace(/0+$/, '');
    return `${whole}.${fracStr}`;
}

/**
 * Format Planck as human-readable string with units
 * @param planck Amount in Planck
 * @returns e.g. "1.5 DOT" or "500,000 Planck"
 */
export function formatDOTPlanck(planck: bigint): string {
    if (planck >= PLANCK_PER_DOT) {
        return `${planckToDot(planck)} DOT`;
    }
    return `${planck.toLocaleString()} Planck`;
}

// =============================================================================
// VALIDATION UTILITIES
// =============================================================================

/**
 * Validate a Substrate address (32-byte hex, 0x-prefixed, 64 hex chars)
 * @param address Substrate address string (bytes32 encoded)
 * @returns True if the address format appears valid
 */
export function isValidSubstrateAddress(address: string): boolean {
    return /^0x[0-9a-fA-F]{64}$/.test(address);
}

/**
 * Validate a deposit amount is within bridge limits
 * @param amountPlanck Amount in Planck
 * @returns Object with valid flag and error message if invalid
 */
export function validateDOTDepositAmount(amountPlanck: bigint): {
    valid: boolean;
    error?: string;
} {
    if (amountPlanck < MIN_DEPOSIT_PLANCK) {
        return {
            valid: false,
            error: `Amount ${formatDOTPlanck(amountPlanck)} is below minimum deposit of ${formatDOTPlanck(MIN_DEPOSIT_PLANCK)}`,
        };
    }
    if (amountPlanck > MAX_DEPOSIT_PLANCK) {
        return {
            valid: false,
            error: `Amount ${formatDOTPlanck(amountPlanck)} exceeds maximum deposit of ${formatDOTPlanck(MAX_DEPOSIT_PLANCK)}`,
        };
    }
    return { valid: true };
}

// =============================================================================
// FEE CALCULATIONS
// =============================================================================

/**
 * Calculate the bridge fee for a given amount
 * @param amountPlanck Gross amount in Planck
 * @returns Fee in Planck (0.06% by default)
 */
export function calculatePolkadotBridgeFee(amountPlanck: bigint): bigint {
    return (amountPlanck * DOT_BRIDGE_FEE_BPS) / DOT_BPS_DENOMINATOR;
}

/**
 * Calculate the net amount after bridge fee
 * @param amountPlanck Gross amount in Planck
 * @returns Net amount in Planck
 */
export function calculatePolkadotNetAmount(amountPlanck: bigint): bigint {
    return amountPlanck - calculatePolkadotBridgeFee(amountPlanck);
}

// =============================================================================
// ESCROW UTILITIES
// =============================================================================

/**
 * Generate a random preimage for HTLC escrow
 * @returns 32-byte hex preimage
 */
export function generatePolkadotPreimage(): `0x${string}` {
    const bytes = new Uint8Array(32);
    crypto.getRandomValues(bytes);
    return `0x${Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('')}`;
}

/**
 * Compute the SHA-256 hashlock from a preimage
 * @param preimage The 32-byte hex preimage
 * @returns SHA-256 hash of the preimage
 */
export async function computePolkadotHashlock(preimage: `0x${string}`): Promise<`0x${string}`> {
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
export function validatePolkadotEscrowTimelocks(
    finishAfter: number,
    cancelAfter: number
): { valid: boolean; error?: string } {
    const now = Math.floor(Date.now() / 1000);

    if (finishAfter <= now) {
        return { valid: false, error: 'finishAfter must be in the future' };
    }

    const duration = cancelAfter - finishAfter;

    if (duration < DOT_MIN_ESCROW_TIMELOCK) {
        return {
            valid: false,
            error: `Escrow duration ${duration}s is below minimum ${DOT_MIN_ESCROW_TIMELOCK}s (1 hour)`,
        };
    }

    if (duration > DOT_MAX_ESCROW_TIMELOCK) {
        return {
            valid: false,
            error: `Escrow duration ${duration}s exceeds maximum ${DOT_MAX_ESCROW_TIMELOCK}s (30 days)`,
        };
    }

    return { valid: true };
}

// =============================================================================
// TIMING UTILITIES
// =============================================================================

/**
 * Estimate GRANDPA finality time
 * @param confirmations Number of block confirmations (default: 2)
 * @returns Estimated time in milliseconds
 */
export function estimatePolkadotFinalityMs(confirmations?: number): number {
    const n = confirmations ?? DEFAULT_FINALITY_CONFIRMATIONS;
    return n * DOT_BLOCK_TIME_MS;
}

/**
 * Check if a withdrawal is eligible for refund
 * @param initiatedAt Timestamp when withdrawal was initiated (UNIX seconds)
 * @returns True if the refund delay (24 hours) has passed
 */
export function isPolkadotRefundEligible(initiatedAt: number): boolean {
    const now = Math.floor(Date.now() / 1000);
    return now >= initiatedAt + DOT_WITHDRAWAL_REFUND_DELAY;
}

/**
 * Estimate remaining time until epoch change
 * @param epochStartMs Epoch start time in milliseconds
 * @returns Remaining time in milliseconds (0 if epoch should have ended)
 */
export function estimateRemainingEpochMs(epochStartMs: number): number {
    const now = Date.now();
    const epochEnd = epochStartMs + POLKADOT_EPOCH_DURATION_MS;
    return Math.max(0, epochEnd - now);
}

/**
 * Estimate time for a given number of relay chain blocks
 * @param blocks Number of relay chain blocks
 * @returns Estimated time in milliseconds
 */
export function estimatePolkadotBlockTimeMs(blocks: number): number {
    return blocks * DOT_BLOCK_TIME_MS;
}

// =============================================================================
// ABI FRAGMENTS
// =============================================================================

export const POLKADOT_BRIDGE_ABI = [
    // Configuration
    'function configure(address polkadotBridgeContract, address wrappedDOT, address validatorOracle, uint256 minValidatorSignatures, uint256 requiredFinalityConfirmations) external',
    'function setTreasury(address _treasury) external',

    // GRANDPA Header Verification
    'function submitGrandpaHeader(uint256 blockNumber, bytes32 blockHash, bytes32 parentHash, bytes32 stateRoot, bytes32 extrinsicsRoot, uint256 setId, uint256 timestamp, (address validator, bytes signature)[] attestations) external',

    // Deposits (Polkadot → Soul)
    'function initiateDOTDeposit(bytes32 substrateBlockHash, bytes32 substrateSender, address evmRecipient, uint256 amountPlanck, uint256 blockNumber, (bytes32[] trieNodes, bytes32 key, bytes32 value, bytes32 stateRoot) stateProof, (address validator, bytes signature)[] attestations) external returns (bytes32)',
    'function completeDOTDeposit(bytes32 depositId) external',

    // Withdrawals (Soul → Polkadot)
    'function initiateWithdrawal(bytes32 substrateRecipient, uint256 amountPlanck) external returns (bytes32)',
    'function completeWithdrawal(bytes32 withdrawalId, bytes32 substrateTxHash, (bytes32[] trieNodes, bytes32 key, bytes32 value, bytes32 stateRoot) stateProof, (address validator, bytes signature)[] attestations) external',
    'function refundWithdrawal(bytes32 withdrawalId) external',

    // Escrow (Atomic Swaps)
    'function createEscrow(bytes32 substrateParty, bytes32 hashlock, uint256 finishAfter, uint256 cancelAfter) external payable returns (bytes32)',
    'function finishEscrow(bytes32 escrowId, bytes32 preimage) external',
    'function cancelEscrow(bytes32 escrowId) external',

    // Privacy
    'function registerPrivateDeposit(bytes32 depositId, bytes32 commitment, bytes32 nullifier, bytes zkProof) external',

    // Admin
    'function pause() external',
    'function unpause() external',
    'function withdrawFees() external',

    // Views
    'function getDeposit(bytes32 depositId) external view returns (tuple)',
    'function getWithdrawal(bytes32 withdrawalId) external view returns (tuple)',
    'function getEscrow(bytes32 escrowId) external view returns (tuple)',
    'function getGrandpaHeader(bytes32 blockHash) external view returns (tuple)',
    'function getUserDeposits(address user) external view returns (bytes32[])',
    'function getUserWithdrawals(address user) external view returns (bytes32[])',
    'function getUserEscrows(address user) external view returns (bytes32[])',
    'function getBridgeStats() external view returns (uint256, uint256, uint256, uint256, uint256, uint256, uint256)',

    // Constants
    'function POLKADOT_CHAIN_ID() view returns (uint256)',
    'function PLANCK_PER_DOT() view returns (uint256)',
    'function MIN_DEPOSIT_PLANCK() view returns (uint256)',
    'function MAX_DEPOSIT_PLANCK() view returns (uint256)',
    'function BRIDGE_FEE_BPS() view returns (uint256)',
    'function WITHDRAWAL_REFUND_DELAY() view returns (uint256)',
    'function DEFAULT_FINALITY_CONFIRMATIONS() view returns (uint256)',

    // State
    'function depositNonce() view returns (uint256)',
    'function withdrawalNonce() view returns (uint256)',
    'function escrowNonce() view returns (uint256)',
    'function latestBlockNumber() view returns (uint256)',
    'function currentSetId() view returns (uint256)',
    'function totalDeposited() view returns (uint256)',
    'function totalWithdrawn() view returns (uint256)',
    'function accumulatedFees() view returns (uint256)',
    'function treasury() view returns (address)',
    'function usedSubstrateTxHashes(bytes32) view returns (bool)',
    'function usedNullifiers(bytes32) view returns (bool)',

    // Events
    'event BridgeConfigured(address indexed polkadotBridgeContract, address wrappedDOT, address validatorOracle)',
    'event GrandpaHeaderSubmitted(uint256 indexed blockNumber, bytes32 indexed blockHash, bytes32 stateRoot, uint256 setId)',
    'event DOTDepositInitiated(bytes32 indexed depositId, bytes32 indexed substrateBlockHash, bytes32 substrateSender, address indexed evmRecipient, uint256 amountPlanck)',
    'event DOTDepositCompleted(bytes32 indexed depositId, address indexed evmRecipient, uint256 amountPlanck)',
    'event DOTWithdrawalInitiated(bytes32 indexed withdrawalId, address indexed evmSender, bytes32 substrateRecipient, uint256 amountPlanck)',
    'event DOTWithdrawalCompleted(bytes32 indexed withdrawalId, bytes32 substrateTxHash)',
    'event DOTWithdrawalRefunded(bytes32 indexed withdrawalId, address indexed evmSender, uint256 amountPlanck)',
    'event EscrowCreated(bytes32 indexed escrowId, address indexed evmParty, bytes32 substrateParty, uint256 amountPlanck, bytes32 hashlock)',
    'event EscrowFinished(bytes32 indexed escrowId, bytes32 preimage)',
    'event EscrowCancelled(bytes32 indexed escrowId)',
    'event PrivateDepositRegistered(bytes32 indexed depositId, bytes32 commitment, bytes32 nullifier)',
    'event FeesWithdrawn(address indexed recipient, uint256 amount)',
] as const;

export const WRAPPED_DOT_ABI = [
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
