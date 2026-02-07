/**
 * Soul Protocol - Berachain Bridge SDK Module
 *
 * TypeScript utilities and types for interacting with the BerachainBridgeAdapter contract.
 * Provides Berachain-specific helpers: wei conversions, address validation,
 * fee calculations, CometBFT block proof utilities, and escrow helpers.
 *
 * Berachain is an EVM-compatible Layer 1 built on BeaconKit using CometBFT consensus
 * (derived from Tendermint). It features ~5s block times, Proof-of-Liquidity (PoL)
 * consensus mechanism, single-slot finality via CometBFT, and 18-decimal precision
 * (wei) for its native BERA token.
 *
 * @example
 * ```typescript
 * import { beraToWei, weiToBera, calculateBerachainBridgeFee, BERACHAIN_BRIDGE_ABI } from './berachain';
 *
 * const amount = beraToWei(10); // 10_000_000_000_000_000_000n (10 BERA in wei)
 * const fee = calculateBerachainBridgeFee(amount); // 4_000_000_000_000_000n (0.04%)
 * ```
 */

// =============================================================================
// CONSTANTS
// =============================================================================

/** 1 BERA = 1e18 wei (18 decimals) */
export const WEI_PER_BERA = 10n ** 18n;

/** Minimum deposit: 0.01 BERA (1e16 wei) */
export const BERA_MIN_DEPOSIT_WEI = 10n ** 16n;

/** Maximum deposit: 10,000,000 BERA */
export const BERA_MAX_DEPOSIT_WEI = 10_000_000n * WEI_PER_BERA;

/** Bridge fee: 4 BPS (0.04%) */
export const BERA_BRIDGE_FEE_BPS = 4n;

/** BPS denominator */
export const BERA_BPS_DENOMINATOR = 10_000n;

/** Minimum escrow timelock: 1 hour */
export const BERA_MIN_ESCROW_TIMELOCK = 3600;

/** Maximum escrow timelock: 30 days */
export const BERA_MAX_ESCROW_TIMELOCK = 30 * 24 * 3600;

/** Withdrawal refund delay: 24 hours */
export const BERA_WITHDRAWAL_REFUND_DELAY = 24 * 3600;

/** Default block confirmations for finality */
export const BERA_DEFAULT_BLOCK_CONFIRMATIONS = 1;

/** Berachain block time in ms (~5s CometBFT/BeaconKit consensus) */
export const BERA_BLOCK_TIME_MS = 5000;

/** Berachain mainnet chain ID */
export const BERACHAIN_CHAIN_ID = 80094;

/** Berachain epoch duration (~6 hours) */
export const BERACHAIN_EPOCH_DURATION_MS = 6 * 60 * 60 * 1000;

// =============================================================================
// ENUMS
// =============================================================================

export enum BERADepositStatus {
    PENDING = 0,
    VERIFIED = 1,
    COMPLETED = 2,
    FAILED = 3,
}

export enum BERAWithdrawalStatus {
    PENDING = 0,
    PROCESSING = 1,
    COMPLETED = 2,
    REFUNDED = 3,
    FAILED = 4,
}

export enum BERAEscrowStatus {
    ACTIVE = 0,
    FINISHED = 1,
    CANCELLED = 2,
}

export enum BerachainBridgeOpType {
    BERA_TRANSFER = 0,
    ERC20_TRANSFER = 1,
    VALIDATOR_UPDATE = 2,
    EMERGENCY_OP = 3,
}

// =============================================================================
// TYPES
// =============================================================================

export interface BERADeposit {
    depositId: `0x${string}`;
    beraTxHash: `0x${string}`;
    beraSender: `0x${string}`;
    evmRecipient: `0x${string}`;
    amountWei: bigint;
    netAmountWei: bigint;
    fee: bigint;
    status: BERADepositStatus;
    blockNumber: bigint;
    initiatedAt: bigint;
    completedAt: bigint;
}

export interface BERAWithdrawal {
    withdrawalId: `0x${string}`;
    evmSender: `0x${string}`;
    beraRecipient: `0x${string}`;
    amountWei: bigint;
    beraTxHash: `0x${string}`;
    status: BERAWithdrawalStatus;
    initiatedAt: bigint;
    completedAt: bigint;
}

export interface BERAEscrow {
    escrowId: `0x${string}`;
    evmParty: `0x${string}`;
    beraParty: `0x${string}`;
    amountWei: bigint;
    hashlock: `0x${string}`;
    preimage: `0x${string}`;
    finishAfter: bigint;
    cancelAfter: bigint;
    status: BERAEscrowStatus;
    createdAt: bigint;
}

export interface BerachainBridgeConfig {
    berachainBridgeContract: `0x${string}`;
    wrappedBERA: `0x${string}`;
    validatorOracle: `0x${string}`;
    minValidatorSignatures: bigint;
    requiredBlockConfirmations: bigint;
    active: boolean;
}

export interface CometBFTBlock {
    blockNumber: bigint;
    blockHash: `0x${string}`;
    appHash: `0x${string}`;
    validatorsHash: `0x${string}`;
    round: bigint;
    timestamp: bigint;
    verified: boolean;
}

export interface CometBFTProof {
    merkleProof: `0x${string}`[];
    blockIndex: bigint;
    leafHash: `0x${string}`;
}

export interface ValidatorAttestation {
    validator: `0x${string}`;
    signature: `0x${string}`;
}

export interface BerachainBridgeStats {
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
 * Convert BERA to wei (smallest unit)
 * @param bera Amount in BERA (supports decimals as string)
 * @returns Amount in wei as bigint
 */
export function beraToWei(bera: number | string): bigint {
    if (typeof bera === 'string') {
        const parts = bera.split('.');
        const whole = BigInt(parts[0]) * WEI_PER_BERA;
        if (parts.length === 1) return whole;

        const decStr = parts[1].padEnd(18, '0').slice(0, 18);
        return whole + BigInt(decStr);
    }
    return beraToWei(bera.toString());
}

/**
 * Convert wei to BERA string
 * @param wei Amount in wei
 * @returns Formatted BERA amount string (up to 18 decimals)
 */
export function weiToBera(wei: bigint): string {
    const whole = wei / WEI_PER_BERA;
    const remainder = wei % WEI_PER_BERA;

    if (remainder === 0n) return whole.toString();

    const fracStr = remainder.toString().padStart(18, '0').replace(/0+$/, '');
    return `${whole}.${fracStr}`;
}

/**
 * Format wei as human-readable string with units
 * @param wei Amount in wei
 * @returns e.g. "1.5 BERA" or "500,000 wei"
 */
export function formatBERAWei(wei: bigint): string {
    if (wei >= WEI_PER_BERA) {
        return `${weiToBera(wei)} BERA`;
    }
    return `${wei.toLocaleString()} wei`;
}

// =============================================================================
// VALIDATION UTILITIES
// =============================================================================

/**
 * Validate a Berachain address (20-byte hex, 0x-prefixed, 40 hex chars)
 * @param address Berachain address string
 * @returns True if the address format appears valid
 */
export function isValidBeraAddress(address: string): boolean {
    return /^0x[0-9a-fA-F]{40}$/.test(address);
}

/**
 * Validate a deposit amount is within bridge limits
 * @param amountWei Amount in wei
 * @returns Object with valid flag and error message if invalid
 */
export function validateBERADepositAmount(amountWei: bigint): {
    valid: boolean;
    error?: string;
} {
    if (amountWei < BERA_MIN_DEPOSIT_WEI) {
        return {
            valid: false,
            error: `Amount ${formatBERAWei(amountWei)} is below minimum deposit of ${formatBERAWei(BERA_MIN_DEPOSIT_WEI)}`,
        };
    }
    if (amountWei > BERA_MAX_DEPOSIT_WEI) {
        return {
            valid: false,
            error: `Amount ${formatBERAWei(amountWei)} exceeds maximum deposit of ${formatBERAWei(BERA_MAX_DEPOSIT_WEI)}`,
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
export function calculateBerachainBridgeFee(amountWei: bigint): bigint {
    return (amountWei * BERA_BRIDGE_FEE_BPS) / BERA_BPS_DENOMINATOR;
}

/**
 * Calculate the net amount after bridge fee
 * @param amountWei Gross amount in wei
 * @returns Net amount in wei
 */
export function calculateBerachainNetAmount(amountWei: bigint): bigint {
    return amountWei - calculateBerachainBridgeFee(amountWei);
}

// =============================================================================
// ESCROW UTILITIES
// =============================================================================

/**
 * Generate a random preimage for HTLC escrow
 * @returns 32-byte hex preimage
 */
export function generateBerachainPreimage(): `0x${string}` {
    const bytes = new Uint8Array(32);
    crypto.getRandomValues(bytes);
    return `0x${Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('')}`;
}

/**
 * Compute the SHA-256 hashlock from a preimage
 * @param preimage The 32-byte hex preimage
 * @returns SHA-256 hash of the preimage
 */
export async function computeBerachainHashlock(preimage: `0x${string}`): Promise<`0x${string}`> {
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
export function validateBerachainEscrowTimelocks(
    finishAfter: number,
    cancelAfter: number
): { valid: boolean; error?: string } {
    const now = Math.floor(Date.now() / 1000);

    if (finishAfter <= now) {
        return { valid: false, error: 'finishAfter must be in the future' };
    }

    const duration = cancelAfter - finishAfter;

    if (duration < BERA_MIN_ESCROW_TIMELOCK) {
        return {
            valid: false,
            error: `Escrow duration ${duration}s is below minimum ${BERA_MIN_ESCROW_TIMELOCK}s (1 hour)`,
        };
    }

    if (duration > BERA_MAX_ESCROW_TIMELOCK) {
        return {
            valid: false,
            error: `Escrow duration ${duration}s exceeds maximum ${BERA_MAX_ESCROW_TIMELOCK}s (30 days)`,
        };
    }

    return { valid: true };
}

// =============================================================================
// TIMING UTILITIES
// =============================================================================

/**
 * Estimate block finalization time on Berachain
 * @param confirmations Number of block confirmations (default: 1)
 * @returns Estimated time in milliseconds
 */
export function estimateBerachainBlockFinalityMs(confirmations?: number): number {
    const n = confirmations ?? BERA_DEFAULT_BLOCK_CONFIRMATIONS;
    return n * BERA_BLOCK_TIME_MS;
}

/**
 * Check if a withdrawal is eligible for refund
 * @param initiatedAt Timestamp when withdrawal was initiated (UNIX seconds)
 * @returns True if the refund delay (24 hours) has passed
 */
export function isBerachainRefundEligible(initiatedAt: number): boolean {
    const now = Math.floor(Date.now() / 1000);
    return now >= initiatedAt + BERA_WITHDRAWAL_REFUND_DELAY;
}

/**
 * Estimate remaining time until epoch change
 * @param epochStartMs Epoch start time in milliseconds
 * @returns Remaining time in milliseconds (0 if epoch should have ended)
 */
export function estimateRemainingEpochMs(epochStartMs: number): number {
    const now = Date.now();
    const epochEnd = epochStartMs + BERACHAIN_EPOCH_DURATION_MS;
    return Math.max(0, epochEnd - now);
}

/**
 * Estimate time for a given number of CometBFT consensus rounds
 * @param rounds Number of consensus rounds
 * @returns Estimated time in milliseconds
 */
export function estimateBerachainConsensusTimeMs(rounds: number): number {
    return rounds * BERA_BLOCK_TIME_MS;
}

// =============================================================================
// ABI FRAGMENTS
// =============================================================================

export const BERACHAIN_BRIDGE_ABI = [
    // Configuration
    'function configure(address berachainBridgeContract, address wrappedBERA, address validatorOracle, uint256 minValidatorSignatures, uint256 requiredBlockConfirmations) external',
    'function setTreasury(address _treasury) external',

    // Deposits (Berachain → Soul)
    'function initiateBERADeposit(bytes32 beraTxHash, address beraSender, address evmRecipient, uint256 amountWei, uint256 blockNumber, (bytes32[] merkleProof, uint256 blockIndex, bytes32 leafHash) txProof, (address validator, bytes signature)[] attestations) external returns (bytes32)',
    'function completeBERADeposit(bytes32 depositId) external',

    // Withdrawals (Soul → Berachain)
    'function initiateWithdrawal(address beraRecipient, uint256 amountWei) external returns (bytes32)',
    'function completeWithdrawal(bytes32 withdrawalId, bytes32 beraTxHash, (bytes32[] merkleProof, uint256 blockIndex, bytes32 leafHash) txProof, (address validator, bytes signature)[] attestations) external',
    'function refundWithdrawal(bytes32 withdrawalId) external',

    // Escrow (Atomic Swaps)
    'function createEscrow(address beraParty, bytes32 hashlock, uint256 finishAfter, uint256 cancelAfter) external payable returns (bytes32)',
    'function finishEscrow(bytes32 escrowId, bytes32 preimage) external',
    'function cancelEscrow(bytes32 escrowId) external',

    // Privacy
    'function registerPrivateDeposit(bytes32 depositId, bytes32 commitment, bytes32 nullifier, bytes zkProof) external',

    // CometBFT Block Verification
    'function submitCometBFTBlock(uint256 blockNumber, bytes32 blockHash, bytes32 appHash, bytes32 validatorsHash, uint256 round, uint256 timestamp, (address validator, bytes signature)[] attestations) external',

    // Views
    'function getDeposit(bytes32 depositId) external view returns (tuple)',
    'function getWithdrawal(bytes32 withdrawalId) external view returns (tuple)',
    'function getEscrow(bytes32 escrowId) external view returns (tuple)',
    'function getCometBFTBlock(uint256 blockNumber) external view returns (tuple)',
    'function getUserDeposits(address user) external view returns (bytes32[])',
    'function getUserWithdrawals(address user) external view returns (bytes32[])',
    'function getUserEscrows(address user) external view returns (bytes32[])',
    'function getBridgeStats() external view returns (uint256, uint256, uint256, uint256, uint256, uint256, uint256)',

    // Admin
    'function pause() external',
    'function unpause() external',
    'function withdrawFees() external',

    // Constants
    'function BERACHAIN_CHAIN_ID() view returns (uint256)',
    'function WEI_PER_BERA() view returns (uint256)',
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
    'function usedBeraTxHashes(bytes32) view returns (bool)',
    'function usedNullifiers(bytes32) view returns (bool)',

    // Events
    'event BridgeConfigured(address indexed berachainBridgeContract, address wrappedBERA, address validatorOracle)',
    'event BERADepositInitiated(bytes32 indexed depositId, bytes32 indexed beraTxHash, address beraSender, address indexed evmRecipient, uint256 amountWei)',
    'event BERADepositCompleted(bytes32 indexed depositId, address indexed evmRecipient, uint256 amountWei)',
    'event BERAWithdrawalInitiated(bytes32 indexed withdrawalId, address indexed evmSender, address beraRecipient, uint256 amountWei)',
    'event BERAWithdrawalCompleted(bytes32 indexed withdrawalId, bytes32 beraTxHash)',
    'event BERAWithdrawalRefunded(bytes32 indexed withdrawalId, address indexed evmSender, uint256 amountWei)',
    'event EscrowCreated(bytes32 indexed escrowId, address indexed evmParty, address beraParty, uint256 amountWei, bytes32 hashlock)',
    'event EscrowFinished(bytes32 indexed escrowId, bytes32 preimage)',
    'event EscrowCancelled(bytes32 indexed escrowId)',
    'event CometBFTBlockVerified(uint256 indexed blockNumber, bytes32 blockHash, bytes32 appHash)',
    'event PrivateDepositRegistered(bytes32 indexed depositId, bytes32 commitment, bytes32 nullifier)',
    'event FeesWithdrawn(address indexed recipient, uint256 amount)',
] as const;

export const WRAPPED_BERA_ABI = [
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
