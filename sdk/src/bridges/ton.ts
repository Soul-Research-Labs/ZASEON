/**
 * Soul Protocol - TON Bridge SDK Module
 *
 * TypeScript utilities and types for interacting with the TONBridgeAdapter contract.
 * Provides TON-specific helpers: nanoton conversions, workchain address validation,
 * fee calculations, masterchain block utilities, and escrow helpers.
 *
 * TON (The Open Network) is a Layer 1 blockchain using the Catchain BFT consensus
 * protocol with ~5s block finality. It features a multi-chain architecture with a
 * masterchain coordinating up to 2^32 workchains, each containing up to 2^60 shards.
 * Addresses are 256-bit workchain addresses, and the smallest unit is the nanoton
 * (1 TON = 1,000,000,000 nanoton, 9 decimals).
 *
 * @example
 * ```typescript
 * import { tonToNanoton, nanotonToTon, calculateTONBridgeFee, TON_BRIDGE_ABI } from './ton';
 *
 * const amount = tonToNanoton(50); // 50_000_000_000n (50 TON in nanoton)
 * const fee = calculateTONBridgeFee(amount); // 25_000_000n (0.05%)
 * ```
 */

// =============================================================================
// CONSTANTS
// =============================================================================

/** 1 TON = 1e9 nanoton (9 decimals) */
export const NANOTON_PER_TON = 1_000_000_000n;

/** Minimum deposit: 0.1 TON (100,000,000 nanoton) */
export const TON_MIN_DEPOSIT_NANOTON = 100_000_000n;

/** Maximum deposit: 10,000,000 TON */
export const TON_MAX_DEPOSIT_NANOTON = 10_000_000n * NANOTON_PER_TON;

/** Bridge fee: 5 BPS (0.05%) */
export const TON_BRIDGE_FEE_BPS = 5n;

/** BPS denominator */
export const TON_BPS_DENOMINATOR = 10_000n;

/** Minimum escrow timelock: 1 hour */
export const TON_MIN_ESCROW_TIMELOCK = 3600;

/** Maximum escrow timelock: 14 days */
export const TON_MAX_ESCROW_TIMELOCK = 14 * 24 * 3600;

/** Withdrawal refund delay: 24 hours */
export const TON_WITHDRAWAL_REFUND_DELAY = 24 * 3600;

/** Default block confirmations for finality */
export const TON_DEFAULT_BLOCK_CONFIRMATIONS = 1;

/** TON block time in ms (~5s Catchain BFT consensus) */
export const TON_BLOCK_TIME_MS = 5000;

/** TON mainnet chain ID */
export const TON_CHAIN_ID = 239;

/** TON masterchain workchain ID */
export const TON_MASTERCHAIN_WORKCHAIN = -1;

/** TON basechain (default workchain) ID */
export const TON_BASECHAIN_WORKCHAIN = 0;

/** TON validation round duration (~65536 seconds, ~18.2 hours) */
export const TON_VALIDATION_ROUND_MS = 65536 * 1000;

// =============================================================================
// ENUMS
// =============================================================================

export enum TONDepositStatus {
    PENDING = 0,
    VERIFIED = 1,
    COMPLETED = 2,
    FAILED = 3,
}

export enum TONWithdrawalStatus {
    PENDING = 0,
    PROCESSING = 1,
    COMPLETED = 2,
    REFUNDED = 3,
    FAILED = 4,
}

export enum TONEscrowStatus {
    ACTIVE = 0,
    FINISHED = 1,
    CANCELLED = 2,
}

export enum TONBridgeOpType {
    TON_TRANSFER = 0,
    JETTON_TRANSFER = 1,
    CONTRACT_MESSAGE = 2,
    EMERGENCY_OP = 3,
}

// =============================================================================
// TYPES
// =============================================================================

export interface TONDeposit {
    depositId: `0x${string}`;
    tonTxHash: `0x${string}`;
    tonSender: `0x${string}`; // bytes32 TON workchain address (256-bit)
    evmRecipient: `0x${string}`;
    amountNanoton: bigint;
    netAmountNanoton: bigint;
    fee: bigint;
    status: TONDepositStatus;
    seqno: bigint;
    initiatedAt: bigint;
    completedAt: bigint;
}

export interface TONWithdrawal {
    withdrawalId: `0x${string}`;
    evmSender: `0x${string}`;
    tonRecipient: `0x${string}`; // bytes32 TON workchain address (256-bit)
    amountNanoton: bigint;
    tonTxHash: `0x${string}`;
    status: TONWithdrawalStatus;
    initiatedAt: bigint;
    completedAt: bigint;
}

export interface TONEscrow {
    escrowId: `0x${string}`;
    evmParty: `0x${string}`;
    tonParty: `0x${string}`; // bytes32 TON workchain address (256-bit)
    amountNanoton: bigint;
    hashlock: `0x${string}`;
    preimage: `0x${string}`;
    finishAfter: bigint;
    cancelAfter: bigint;
    status: TONEscrowStatus;
    createdAt: bigint;
}

export interface TONBridgeConfig {
    tonBridgeContract: `0x${string}`;
    wrappedTON: `0x${string}`;
    validatorOracle: `0x${string}`;
    minValidatorSignatures: bigint;
    requiredBlockConfirmations: bigint;
    active: boolean;
}

export interface MasterchainBlock {
    seqno: bigint;
    rootHash: `0x${string}`;
    fileHash: `0x${string}`;
    workchain: number;
    shardId: bigint;
    timestamp: bigint;
    verified: boolean;
}

export interface TONStateProof {
    merkleProof: `0x${string}`[];
    blockIndex: bigint;
    leafHash: `0x${string}`;
}

export interface TONBridgeStats {
    totalDeposited: bigint;
    totalWithdrawn: bigint;
    totalEscrows: bigint;
    totalEscrowsFinished: bigint;
    totalEscrowsCancelled: bigint;
    accumulatedFees: bigint;
    latestSeqno: bigint;
}

// =============================================================================
// CONVERSION UTILITIES
// =============================================================================

/**
 * Convert TON to nanoton (smallest unit)
 * @param ton Amount in TON (supports decimals as string)
 * @returns Amount in nanoton as bigint
 */
export function tonToNanoton(ton: number | string): bigint {
    if (typeof ton === 'string') {
        const parts = ton.split('.');
        const whole = BigInt(parts[0]) * NANOTON_PER_TON;
        if (parts.length === 1) return whole;

        const decStr = parts[1].padEnd(9, '0').slice(0, 9);
        return whole + BigInt(decStr);
    }
    return tonToNanoton(ton.toString());
}

/**
 * Convert nanoton to TON string
 * @param nanoton Amount in nanoton
 * @returns Formatted TON amount string (up to 9 decimals)
 */
export function nanotonToTon(nanoton: bigint): string {
    const whole = nanoton / NANOTON_PER_TON;
    const remainder = nanoton % NANOTON_PER_TON;

    if (remainder === 0n) return whole.toString();

    const fracStr = remainder.toString().padStart(9, '0').replace(/0+$/, '');
    return `${whole}.${fracStr}`;
}

/**
 * Format nanoton as human-readable string with units
 * @param nanoton Amount in nanoton
 * @returns e.g. "1.5 TON" or "500,000 nanoton"
 */
export function formatTONNanoton(nanoton: bigint): string {
    if (nanoton >= NANOTON_PER_TON) {
        return `${nanotonToTon(nanoton)} TON`;
    }
    return `${nanoton.toLocaleString()} nanoton`;
}

/**
 * Convert a workchain address to a full TON address string
 * @param workchain Workchain ID (0 for basechain, -1 for masterchain)
 * @param addressHex 256-bit hex address (without 0x prefix)
 * @returns Formatted workchain:address string
 */
export function formatTONWorkchainAddress(workchain: number, addressHex: string): string {
    const normalized = addressHex.startsWith('0x') ? addressHex.slice(2) : addressHex;
    return `${workchain}:${normalized.toLowerCase().padStart(64, '0')}`;
}

// =============================================================================
// VALIDATION UTILITIES
// =============================================================================

/**
 * Validate a TON address in raw format (workchain:hex256)
 * Supports both basechain (0:...) and masterchain (-1:...) addresses
 * @param address TON address string in workchain:hex format
 * @returns True if the address format appears valid
 */
export function isValidTONAddress(address: string): boolean {
    // Raw format: <workchain_id>:<64 hex chars>
    const rawMatch = /^(-1|0):[0-9a-fA-F]{64}$/.test(address);
    if (rawMatch) return true;

    // Also accept 0x-prefixed 32-byte hex (EVM bridged representation)
    if (/^0x[0-9a-fA-F]{64}$/.test(address)) return true;

    return false;
}

/**
 * Validate a user-friendly TON address (base64url encoded, 48 chars)
 * @param address TON user-friendly address string
 * @returns True if the address format appears valid
 */
export function isValidTONFriendlyAddress(address: string): boolean {
    // User-friendly format: base64url, 48 characters (36 bytes encoded)
    return /^[A-Za-z0-9_-]{48}$/.test(address);
}

/**
 * Validate a deposit amount is within bridge limits
 * @param amountNanoton Amount in nanoton
 * @returns Object with valid flag and error message if invalid
 */
export function validateTONDepositAmount(amountNanoton: bigint): {
    valid: boolean;
    error?: string;
} {
    if (amountNanoton < TON_MIN_DEPOSIT_NANOTON) {
        return {
            valid: false,
            error: `Amount ${formatTONNanoton(amountNanoton)} is below minimum deposit of ${formatTONNanoton(TON_MIN_DEPOSIT_NANOTON)}`,
        };
    }
    if (amountNanoton > TON_MAX_DEPOSIT_NANOTON) {
        return {
            valid: false,
            error: `Amount ${formatTONNanoton(amountNanoton)} exceeds maximum deposit of ${formatTONNanoton(TON_MAX_DEPOSIT_NANOTON)}`,
        };
    }
    return { valid: true };
}

// =============================================================================
// FEE CALCULATIONS
// =============================================================================

/**
 * Calculate the bridge fee for a given amount
 * @param amountNanoton Gross amount in nanoton
 * @returns Fee in nanoton (0.05% by default)
 */
export function calculateTONBridgeFee(amountNanoton: bigint): bigint {
    return (amountNanoton * TON_BRIDGE_FEE_BPS) / TON_BPS_DENOMINATOR;
}

/**
 * Calculate the net amount after bridge fee
 * @param amountNanoton Gross amount in nanoton
 * @returns Net amount in nanoton
 */
export function calculateTONNetAmount(amountNanoton: bigint): bigint {
    return amountNanoton - calculateTONBridgeFee(amountNanoton);
}

// =============================================================================
// ESCROW UTILITIES
// =============================================================================

/**
 * Generate a random preimage for HTLC escrow
 * @returns 32-byte hex preimage
 */
export function generateTONPreimage(): `0x${string}` {
    const bytes = new Uint8Array(32);
    crypto.getRandomValues(bytes);
    return `0x${Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('')}`;
}

/**
 * Compute the SHA-256 hashlock from a preimage
 * @param preimage The 32-byte hex preimage
 * @returns SHA-256 hash of the preimage
 */
export async function computeTONHashlock(preimage: `0x${string}`): Promise<`0x${string}`> {
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
export function validateTONEscrowTimelocks(
    finishAfter: number,
    cancelAfter: number
): { valid: boolean; error?: string } {
    const now = Math.floor(Date.now() / 1000);

    if (finishAfter <= now) {
        return { valid: false, error: 'finishAfter must be in the future' };
    }

    const duration = cancelAfter - finishAfter;

    if (duration < TON_MIN_ESCROW_TIMELOCK) {
        return {
            valid: false,
            error: `Escrow duration ${duration}s is below minimum ${TON_MIN_ESCROW_TIMELOCK}s (1 hour)`,
        };
    }

    if (duration > TON_MAX_ESCROW_TIMELOCK) {
        return {
            valid: false,
            error: `Escrow duration ${duration}s exceeds maximum ${TON_MAX_ESCROW_TIMELOCK}s (14 days)`,
        };
    }

    return { valid: true };
}

// =============================================================================
// TIMING UTILITIES
// =============================================================================

/**
 * Estimate block finalization time on TON masterchain
 * @param confirmations Number of block confirmations (default: 1)
 * @returns Estimated time in milliseconds
 */
export function estimateTONBlockFinalityMs(confirmations?: number): number {
    const n = confirmations ?? TON_DEFAULT_BLOCK_CONFIRMATIONS;
    return n * TON_BLOCK_TIME_MS;
}

/**
 * Check if a withdrawal is eligible for refund
 * @param initiatedAt Timestamp when withdrawal was initiated (UNIX seconds)
 * @returns True if the refund delay (24 hours) has passed
 */
export function isTONRefundEligible(initiatedAt: number): boolean {
    const now = Math.floor(Date.now() / 1000);
    return now >= initiatedAt + TON_WITHDRAWAL_REFUND_DELAY;
}

/**
 * Estimate remaining time until validation round change
 * @param roundStartMs Validation round start time in milliseconds
 * @returns Remaining time in milliseconds (0 if round should have ended)
 */
export function estimateTONRemainingRoundMs(roundStartMs: number): number {
    const now = Date.now();
    const roundEnd = roundStartMs + TON_VALIDATION_ROUND_MS;
    return Math.max(0, roundEnd - now);
}

/**
 * Estimate time for a given number of Catchain BFT consensus rounds
 * @param blocks Number of blocks
 * @returns Estimated time in milliseconds
 */
export function estimateTONConsensusTimeMs(blocks: number): number {
    return blocks * TON_BLOCK_TIME_MS;
}

// =============================================================================
// ABI FRAGMENTS
// =============================================================================

export const TON_BRIDGE_ABI = [
    // Configuration
    'function configure(address tonBridgeContract, address wrappedTON, address validatorOracle, uint256 minValidatorSignatures, uint256 requiredBlockConfirmations) external',
    'function setTreasury(address _treasury) external',

    // Deposits (TON → Soul)
    'function initiateTONDeposit(bytes32 tonTxHash, bytes32 tonSender, address evmRecipient, uint256 amountNanoton, uint256 seqno, (bytes32[] merkleProof, uint256 blockIndex, bytes32 leafHash) stateProof, (address validator, bytes signature)[] attestations) external returns (bytes32)',
    'function completeTONDeposit(bytes32 depositId) external',

    // Withdrawals (Soul → TON)
    'function initiateWithdrawal(bytes32 tonRecipient, uint256 amountNanoton) external returns (bytes32)',
    'function completeWithdrawal(bytes32 withdrawalId, bytes32 tonTxHash, (bytes32[] merkleProof, uint256 blockIndex, bytes32 leafHash) stateProof, (address validator, bytes signature)[] attestations) external',
    'function refundWithdrawal(bytes32 withdrawalId) external',

    // Escrow (Atomic Swaps)
    'function createEscrow(bytes32 tonParty, bytes32 hashlock, uint256 finishAfter, uint256 cancelAfter) external payable returns (bytes32)',
    'function finishEscrow(bytes32 escrowId, bytes32 preimage) external',
    'function cancelEscrow(bytes32 escrowId) external',

    // Privacy
    'function registerPrivateDeposit(bytes32 depositId, bytes32 commitment, bytes32 nullifier, bytes zkProof) external',

    // Masterchain Block Verification
    'function submitMasterchainBlock(uint256 seqno, bytes32 rootHash, bytes32 fileHash, int8 workchain, uint256 shardId, uint256 timestamp, (address validator, bytes signature)[] attestations) external',

    // Views
    'function getDeposit(bytes32 depositId) external view returns (tuple)',
    'function getWithdrawal(bytes32 withdrawalId) external view returns (tuple)',
    'function getEscrow(bytes32 escrowId) external view returns (tuple)',
    'function getMasterchainBlock(uint256 seqno) external view returns (tuple)',
    'function getUserDeposits(address user) external view returns (bytes32[])',
    'function getUserWithdrawals(address user) external view returns (bytes32[])',
    'function getUserEscrows(address user) external view returns (bytes32[])',
    'function getBridgeStats() external view returns (uint256, uint256, uint256, uint256, uint256, uint256, uint256)',

    // Admin
    'function pause() external',
    'function unpause() external',
    'function withdrawFees() external',

    // Constants
    'function TON_CHAIN_ID() view returns (uint256)',
    'function NANOTON_PER_TON() view returns (uint256)',
    'function MIN_DEPOSIT_NANOTON() view returns (uint256)',
    'function MAX_DEPOSIT_NANOTON() view returns (uint256)',
    'function BRIDGE_FEE_BPS() view returns (uint256)',
    'function WITHDRAWAL_REFUND_DELAY() view returns (uint256)',
    'function DEFAULT_BLOCK_CONFIRMATIONS() view returns (uint256)',

    // State
    'function depositNonce() view returns (uint256)',
    'function withdrawalNonce() view returns (uint256)',
    'function escrowNonce() view returns (uint256)',
    'function latestSeqno() view returns (uint256)',
    'function totalDeposited() view returns (uint256)',
    'function totalWithdrawn() view returns (uint256)',
    'function accumulatedFees() view returns (uint256)',
    'function treasury() view returns (address)',
    'function usedTONTxHashes(bytes32) view returns (bool)',
    'function usedNullifiers(bytes32) view returns (bool)',

    // Events
    'event BridgeConfigured(address indexed tonBridgeContract, address wrappedTON, address validatorOracle)',
    'event TONDepositInitiated(bytes32 indexed depositId, bytes32 indexed tonTxHash, bytes32 tonSender, address indexed evmRecipient, uint256 amountNanoton)',
    'event TONDepositCompleted(bytes32 indexed depositId, address indexed evmRecipient, uint256 amountNanoton)',
    'event TONWithdrawalInitiated(bytes32 indexed withdrawalId, address indexed evmSender, bytes32 tonRecipient, uint256 amountNanoton)',
    'event TONWithdrawalCompleted(bytes32 indexed withdrawalId, bytes32 tonTxHash)',
    'event TONWithdrawalRefunded(bytes32 indexed withdrawalId, address indexed evmSender, uint256 amountNanoton)',
    'event EscrowCreated(bytes32 indexed escrowId, address indexed evmParty, bytes32 tonParty, uint256 amountNanoton, bytes32 hashlock)',
    'event EscrowFinished(bytes32 indexed escrowId, bytes32 preimage)',
    'event EscrowCancelled(bytes32 indexed escrowId)',
    'event MasterchainBlockVerified(uint256 indexed seqno, bytes32 rootHash, uint256 timestamp)',
    'event PrivateDepositRegistered(bytes32 indexed depositId, bytes32 commitment, bytes32 nullifier)',
    'event FeesWithdrawn(address indexed recipient, uint256 amount)',
] as const;

export const WRAPPED_TON_ABI = [
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
