/**
 * Soul Protocol - Cardano Bridge SDK Module
 *
 * TypeScript utilities and types for interacting with the CardanoBridgeAdapter contract.
 * Provides Cardano-specific helpers: Lovelace conversions, bech32 address validation,
 * fee calculations, Ouroboros header utilities, and escrow helpers.
 *
 * Cardano is a Layer 1 proof-of-stake blockchain using the Ouroboros Praos consensus
 * protocol with ~20s block time. It features an extended UTXO model with Plutus smart
 * contracts and native multi-asset support. Addresses use bech32 encoding (addr1...),
 * and the smallest unit is the Lovelace (1 ADA = 1,000,000 Lovelace, 6 decimals).
 *
 * @example
 * ```typescript
 * import { adaToLovelace, lovelaceToAda, calculateCardanoBridgeFee, CARDANO_BRIDGE_ABI } from './cardano';
 *
 * const amount = adaToLovelace(100); // 100_000_000n (100 ADA in Lovelace)
 * const fee = calculateCardanoBridgeFee(amount); // 60_000n (0.06%)
 * ```
 */

// =============================================================================
// CONSTANTS
// =============================================================================

/** 1 ADA = 1,000,000 Lovelace (6 decimals) */
export const LOVELACE_PER_ADA = 1_000_000n;

/** Minimum deposit: 0.1 ADA (100,000 Lovelace) */
export const ADA_MIN_DEPOSIT_LOVELACE = 100_000n;

/** Maximum deposit: 10,000,000 ADA */
export const ADA_MAX_DEPOSIT_LOVELACE = 10_000_000n * LOVELACE_PER_ADA;

/** Bridge fee: 6 BPS (0.06%) — higher due to slow finality & UTXO complexity */
export const ADA_BRIDGE_FEE_BPS = 6n;

/** BPS denominator */
export const ADA_BPS_DENOMINATOR = 10_000n;

/** Minimum escrow timelock: 2 hours (longer than EVM chains due to slow finality) */
export const ADA_MIN_ESCROW_TIMELOCK = 2 * 3600;

/** Maximum escrow timelock: 30 days */
export const ADA_MAX_ESCROW_TIMELOCK = 30 * 24 * 3600;

/** Withdrawal refund delay: 48 hours (longer due to slow finality) */
export const ADA_WITHDRAWAL_REFUND_DELAY = 48 * 3600;

/** Default block confirmations for finality */
export const ADA_DEFAULT_BLOCK_CONFIRMATIONS = 36;

/** Cardano block time in ms (~20s Ouroboros Praos) */
export const ADA_BLOCK_TIME_MS = 20_000;

/** Cardano network magic / chain ID */
export const CARDANO_CHAIN_ID = 764824073;

/** Cardano epoch duration (~5 days = 432,000 slots at 1s/slot) */
export const CARDANO_EPOCH_DURATION_MS = 5 * 24 * 60 * 60 * 1000;

/** Cardano slot length in milliseconds */
export const CARDANO_SLOT_LENGTH_MS = 1000;

/** Slots per epoch (432,000) */
export const CARDANO_SLOTS_PER_EPOCH = 432_000;

// =============================================================================
// ENUMS
// =============================================================================

export enum ADADepositStatus {
    PENDING = 0,
    VERIFIED = 1,
    COMPLETED = 2,
    FAILED = 3,
}

export enum ADAWithdrawalStatus {
    PENDING = 0,
    PROCESSING = 1,
    COMPLETED = 2,
    REFUNDED = 3,
    FAILED = 4,
}

export enum ADAEscrowStatus {
    ACTIVE = 0,
    FINISHED = 1,
    CANCELLED = 2,
}

export enum CardanoBridgeOpType {
    ADA_TRANSFER = 0,
    NATIVE_TOKEN_TRANSFER = 1,
    PLUTUS_SCRIPT_EXEC = 2,
    EMERGENCY_OP = 3,
}

// =============================================================================
// TYPES
// =============================================================================

export interface ADADeposit {
    depositId: `0x${string}`;
    cardanoTxHash: `0x${string}`;
    cardanoSender: `0x${string}`; // bytes32 bech32-encoded Cardano address
    evmRecipient: `0x${string}`;
    amountLovelace: bigint;
    netAmountLovelace: bigint;
    fee: bigint;
    status: ADADepositStatus;
    slot: bigint;
    initiatedAt: bigint;
    completedAt: bigint;
}

export interface ADAWithdrawal {
    withdrawalId: `0x${string}`;
    evmSender: `0x${string}`;
    cardanoRecipient: `0x${string}`; // bytes32 bech32-encoded Cardano address
    amountLovelace: bigint;
    cardanoTxHash: `0x${string}`;
    status: ADAWithdrawalStatus;
    initiatedAt: bigint;
    completedAt: bigint;
}

export interface ADAEscrow {
    escrowId: `0x${string}`;
    evmParty: `0x${string}`;
    cardanoParty: `0x${string}`; // bytes32 bech32-encoded Cardano address
    amountLovelace: bigint;
    hashlock: `0x${string}`;
    preimage: `0x${string}`;
    finishAfter: bigint;
    cancelAfter: bigint;
    status: ADAEscrowStatus;
    createdAt: bigint;
}

export interface CardanoBridgeConfig {
    cardanoBridgeContract: `0x${string}`;
    wrappedADA: `0x${string}`;
    oracleRelay: `0x${string}`;
    minValidatorSignatures: bigint;
    requiredBlockConfirmations: bigint;
    active: boolean;
}

export interface OuroborosHeader {
    slot: bigint;
    epoch: bigint;
    blockHash: `0x${string}`;
    prevBlockHash: `0x${string}`;
    vrfOutput: `0x${string}`;
    blockBodyHash: `0x${string}`;
    timestamp: bigint;
    verified: boolean;
}

export interface CardanoStateProof {
    merkleProof: `0x${string}`[];
    blockIndex: bigint;
    leafHash: `0x${string}`;
}

export interface CardanoBridgeStats {
    totalDeposited: bigint;
    totalWithdrawn: bigint;
    totalEscrows: bigint;
    totalEscrowsFinished: bigint;
    totalEscrowsCancelled: bigint;
    accumulatedFees: bigint;
    latestSlot: bigint;
}

// =============================================================================
// CONVERSION UTILITIES
// =============================================================================

/**
 * Convert ADA to Lovelace (smallest unit)
 * @param ada Amount in ADA (supports decimals as string)
 * @returns Amount in Lovelace as bigint
 */
export function adaToLovelace(ada: number | string): bigint {
    if (typeof ada === 'string') {
        const parts = ada.split('.');
        const whole = BigInt(parts[0]) * LOVELACE_PER_ADA;
        if (parts.length === 1) return whole;

        const decStr = parts[1].padEnd(6, '0').slice(0, 6);
        return whole + BigInt(decStr);
    }
    return adaToLovelace(ada.toString());
}

/**
 * Convert Lovelace to ADA string
 * @param lovelace Amount in Lovelace
 * @returns Formatted ADA amount string (up to 6 decimals)
 */
export function lovelaceToAda(lovelace: bigint): string {
    const whole = lovelace / LOVELACE_PER_ADA;
    const remainder = lovelace % LOVELACE_PER_ADA;

    if (remainder === 0n) return whole.toString();

    const fracStr = remainder.toString().padStart(6, '0').replace(/0+$/, '');
    return `${whole}.${fracStr}`;
}

/**
 * Format Lovelace as human-readable string with units
 * @param lovelace Amount in Lovelace
 * @returns e.g. "1.5 ADA" or "500,000 Lovelace"
 */
export function formatADALovelace(lovelace: bigint): string {
    if (lovelace >= LOVELACE_PER_ADA) {
        return `${lovelaceToAda(lovelace)} ADA`;
    }
    return `${lovelace.toLocaleString()} Lovelace`;
}

/**
 * Convert a slot number to an approximate epoch number
 * @param slot Cardano slot number
 * @returns Estimated epoch number
 */
export function slotToEpoch(slot: bigint): bigint {
    return slot / BigInt(CARDANO_SLOTS_PER_EPOCH);
}

// =============================================================================
// VALIDATION UTILITIES
// =============================================================================

/**
 * Validate a Cardano bech32 address (mainnet addr1... or stake1...)
 * @param address Cardano address string
 * @returns True if the address format appears valid
 */
export function isValidCardanoAddress(address: string): boolean {
    // Mainnet payment addresses start with addr1, stake addresses with stake1
    // Testnet uses addr_test1 and stake_test1
    if (/^addr1[a-z0-9]{53,}$/.test(address)) return true;
    if (/^addr_test1[a-z0-9]{53,}$/.test(address)) return true;
    if (/^stake1[a-z0-9]{48,}$/.test(address)) return true;
    if (/^stake_test1[a-z0-9]{48,}$/.test(address)) return true;
    return false;
}

/**
 * Validate a deposit amount is within bridge limits
 * @param amountLovelace Amount in Lovelace
 * @returns Object with valid flag and error message if invalid
 */
export function validateADADepositAmount(amountLovelace: bigint): {
    valid: boolean;
    error?: string;
} {
    if (amountLovelace < ADA_MIN_DEPOSIT_LOVELACE) {
        return {
            valid: false,
            error: `Amount ${formatADALovelace(amountLovelace)} is below minimum deposit of ${formatADALovelace(ADA_MIN_DEPOSIT_LOVELACE)}`,
        };
    }
    if (amountLovelace > ADA_MAX_DEPOSIT_LOVELACE) {
        return {
            valid: false,
            error: `Amount ${formatADALovelace(amountLovelace)} exceeds maximum deposit of ${formatADALovelace(ADA_MAX_DEPOSIT_LOVELACE)}`,
        };
    }
    return { valid: true };
}

// =============================================================================
// FEE CALCULATIONS
// =============================================================================

/**
 * Calculate the bridge fee for a given amount
 * @param amountLovelace Gross amount in Lovelace
 * @returns Fee in Lovelace (0.06% by default)
 */
export function calculateCardanoBridgeFee(amountLovelace: bigint): bigint {
    return (amountLovelace * ADA_BRIDGE_FEE_BPS) / ADA_BPS_DENOMINATOR;
}

/**
 * Calculate the net amount after bridge fee
 * @param amountLovelace Gross amount in Lovelace
 * @returns Net amount in Lovelace
 */
export function calculateCardanoNetAmount(amountLovelace: bigint): bigint {
    return amountLovelace - calculateCardanoBridgeFee(amountLovelace);
}

// =============================================================================
// ESCROW UTILITIES
// =============================================================================

/**
 * Generate a random preimage for HTLC escrow
 * @returns 32-byte hex preimage
 */
export function generateCardanoPreimage(): `0x${string}` {
    const bytes = new Uint8Array(32);
    crypto.getRandomValues(bytes);
    return `0x${Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('')}`;
}

/**
 * Compute the SHA-256 hashlock from a preimage
 * @param preimage The 32-byte hex preimage
 * @returns SHA-256 hash of the preimage
 */
export async function computeCardanoHashlock(preimage: `0x${string}`): Promise<`0x${string}`> {
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
export function validateCardanoEscrowTimelocks(
    finishAfter: number,
    cancelAfter: number
): { valid: boolean; error?: string } {
    const now = Math.floor(Date.now() / 1000);

    if (finishAfter <= now) {
        return { valid: false, error: 'finishAfter must be in the future' };
    }

    const duration = cancelAfter - finishAfter;

    if (duration < ADA_MIN_ESCROW_TIMELOCK) {
        return {
            valid: false,
            error: `Escrow duration ${duration}s is below minimum ${ADA_MIN_ESCROW_TIMELOCK}s (2 hours)`,
        };
    }

    if (duration > ADA_MAX_ESCROW_TIMELOCK) {
        return {
            valid: false,
            error: `Escrow duration ${duration}s exceeds maximum ${ADA_MAX_ESCROW_TIMELOCK}s (30 days)`,
        };
    }

    return { valid: true };
}

// =============================================================================
// TIMING UTILITIES
// =============================================================================

/**
 * Estimate block finalization time on Cardano
 * @param confirmations Number of block confirmations (default: 36)
 * @returns Estimated time in milliseconds
 */
export function estimateCardanoBlockFinalityMs(confirmations?: number): number {
    const n = confirmations ?? ADA_DEFAULT_BLOCK_CONFIRMATIONS;
    return n * ADA_BLOCK_TIME_MS;
}

/**
 * Check if a withdrawal is eligible for refund
 * @param initiatedAt Timestamp when withdrawal was initiated (UNIX seconds)
 * @returns True if the refund delay (48 hours) has passed
 */
export function isCardanoRefundEligible(initiatedAt: number): boolean {
    const now = Math.floor(Date.now() / 1000);
    return now >= initiatedAt + ADA_WITHDRAWAL_REFUND_DELAY;
}

/**
 * Estimate remaining time until epoch change
 * @param epochStartMs Epoch start time in milliseconds
 * @returns Remaining time in milliseconds (0 if epoch should have ended)
 */
export function estimateCardanoRemainingEpochMs(epochStartMs: number): number {
    const now = Date.now();
    const epochEnd = epochStartMs + CARDANO_EPOCH_DURATION_MS;
    return Math.max(0, epochEnd - now);
}

/**
 * Estimate time for a given number of Ouroboros Praos slots
 * @param slots Number of slots
 * @returns Estimated time in milliseconds
 */
export function estimateCardanoSlotTimeMs(slots: number): number {
    return slots * CARDANO_SLOT_LENGTH_MS;
}

/**
 * Estimate time for a given number of Ouroboros Praos blocks
 * @param blocks Number of blocks
 * @returns Estimated time in milliseconds
 */
export function estimateCardanoConsensusTimeMs(blocks: number): number {
    return blocks * ADA_BLOCK_TIME_MS;
}

// =============================================================================
// ABI FRAGMENTS
// =============================================================================

export const CARDANO_BRIDGE_ABI = [
    // Configuration
    'function configure(address cardanoBridgeContract, address wrappedADA, address oracleRelay, uint256 minValidatorSignatures, uint256 requiredBlockConfirmations) external',
    'function setTreasury(address _treasury) external',

    // Deposits (Cardano → Soul)
    'function initiateADADeposit(bytes32 cardanoTxHash, bytes32 cardanoSender, address evmRecipient, uint256 amountLovelace, uint256 slot, (bytes32[] merkleProof, uint256 blockIndex, bytes32 leafHash) stateProof, (address validator, bytes signature)[] attestations) external returns (bytes32)',
    'function completeADADeposit(bytes32 depositId) external',

    // Withdrawals (Soul → Cardano)
    'function initiateWithdrawal(bytes32 cardanoRecipient, uint256 amountLovelace) external returns (bytes32)',
    'function completeWithdrawal(bytes32 withdrawalId, bytes32 cardanoTxHash, (bytes32[] merkleProof, uint256 blockIndex, bytes32 leafHash) stateProof, (address validator, bytes signature)[] attestations) external',
    'function refundWithdrawal(bytes32 withdrawalId) external',

    // Escrow (Atomic Swaps)
    'function createEscrow(bytes32 cardanoParty, bytes32 hashlock, uint256 finishAfter, uint256 cancelAfter) external payable returns (bytes32)',
    'function finishEscrow(bytes32 escrowId, bytes32 preimage) external',
    'function cancelEscrow(bytes32 escrowId) external',

    // Privacy
    'function registerPrivateDeposit(bytes32 depositId, bytes32 commitment, bytes32 nullifier, bytes zkProof) external',

    // Ouroboros Header Verification
    'function submitOuroborosHeader(uint256 slot, uint256 epoch, bytes32 blockHash, bytes32 prevBlockHash, bytes32 vrfOutput, bytes32 blockBodyHash, uint256 timestamp, (address validator, bytes signature)[] attestations) external',

    // Views
    'function getDeposit(bytes32 depositId) external view returns (tuple)',
    'function getWithdrawal(bytes32 withdrawalId) external view returns (tuple)',
    'function getEscrow(bytes32 escrowId) external view returns (tuple)',
    'function getOuroborosHeader(uint256 slot) external view returns (tuple)',
    'function getUserDeposits(address user) external view returns (bytes32[])',
    'function getUserWithdrawals(address user) external view returns (bytes32[])',
    'function getUserEscrows(address user) external view returns (bytes32[])',
    'function getBridgeStats() external view returns (uint256, uint256, uint256, uint256, uint256, uint256, uint256)',

    // Admin
    'function pause() external',
    'function unpause() external',
    'function withdrawFees() external',

    // Constants
    'function CARDANO_CHAIN_ID() view returns (uint256)',
    'function LOVELACE_PER_ADA() view returns (uint256)',
    'function MIN_DEPOSIT_LOVELACE() view returns (uint256)',
    'function MAX_DEPOSIT_LOVELACE() view returns (uint256)',
    'function BRIDGE_FEE_BPS() view returns (uint256)',
    'function WITHDRAWAL_REFUND_DELAY() view returns (uint256)',
    'function DEFAULT_BLOCK_CONFIRMATIONS() view returns (uint256)',

    // State
    'function depositNonce() view returns (uint256)',
    'function withdrawalNonce() view returns (uint256)',
    'function escrowNonce() view returns (uint256)',
    'function latestSlot() view returns (uint256)',
    'function currentEpoch() view returns (uint256)',
    'function totalDeposited() view returns (uint256)',
    'function totalWithdrawn() view returns (uint256)',
    'function accumulatedFees() view returns (uint256)',
    'function treasury() view returns (address)',
    'function usedCardanoTxHashes(bytes32) view returns (bool)',
    'function usedNullifiers(bytes32) view returns (bool)',

    // Events
    'event BridgeConfigured(address indexed cardanoBridgeContract, address wrappedADA, address oracleRelay)',
    'event ADADepositInitiated(bytes32 indexed depositId, bytes32 indexed cardanoTxHash, bytes32 cardanoSender, address indexed evmRecipient, uint256 amountLovelace)',
    'event ADADepositCompleted(bytes32 indexed depositId, address indexed evmRecipient, uint256 amountLovelace)',
    'event ADAWithdrawalInitiated(bytes32 indexed withdrawalId, address indexed evmSender, bytes32 cardanoRecipient, uint256 amountLovelace)',
    'event ADAWithdrawalCompleted(bytes32 indexed withdrawalId, bytes32 cardanoTxHash)',
    'event ADAWithdrawalRefunded(bytes32 indexed withdrawalId, address indexed evmSender, uint256 amountLovelace)',
    'event EscrowCreated(bytes32 indexed escrowId, address indexed evmParty, bytes32 cardanoParty, uint256 amountLovelace, bytes32 hashlock)',
    'event EscrowFinished(bytes32 indexed escrowId, bytes32 preimage)',
    'event EscrowCancelled(bytes32 indexed escrowId)',
    'event OuroborosHeaderVerified(uint256 indexed slot, bytes32 blockHash, uint256 epoch)',
    'event PrivateDepositRegistered(bytes32 indexed depositId, bytes32 commitment, bytes32 nullifier)',
    'event FeesWithdrawn(address indexed recipient, uint256 amount)',
] as const;

export const WRAPPED_ADA_ABI = [
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
