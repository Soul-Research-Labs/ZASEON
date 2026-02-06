/**
 * Soul Protocol - Aptos Bridge SDK Module
 *
 * TypeScript utilities and types for interacting with the AptosBridgeAdapter contract.
 * Provides Aptos-specific helpers: Octas conversions, address validation,
 * fee calculations, ledger info utilities, and escrow helpers.
 *
 * Aptos is a Layer 1 blockchain by Aptos Labs using the Move programming language
 * and AptosBFT (DiemBFT v4) consensus with sub-second finality (~160ms block time).
 * It features Block-STM parallel execution, Jellyfish Merkle Trees for state proofs,
 * and 8-decimal precision (Octas).
 *
 * @example
 * ```typescript
 * import { aptToOctas, octasToApt, calculateAptosBridgeFee, APTOS_BRIDGE_ABI } from './aptos';
 *
 * const amount = aptToOctas(10); // 1_000_000_000n (10 APT in Octas)
 * const fee = calculateAptosBridgeFee(amount); // 400_000n (0.04%)
 * ```
 */

// =============================================================================
// CONSTANTS
// =============================================================================

/** 1 APT = 1e8 Octas (8 decimals) */
export const OCTAS_PER_APT = 100_000_000n;

/** Minimum deposit: 0.1 APT (10,000,000 Octas) */
export const APT_MIN_DEPOSIT_OCTAS = OCTAS_PER_APT / 10n;

/** Maximum deposit: 10,000,000 APT */
export const APT_MAX_DEPOSIT_OCTAS = 10_000_000n * OCTAS_PER_APT;

/** Bridge fee: 4 BPS (0.04%) */
export const APT_BRIDGE_FEE_BPS = 4n;

/** BPS denominator */
export const APT_BPS_DENOMINATOR = 10_000n;

/** Minimum escrow timelock: 1 hour */
export const APT_MIN_ESCROW_TIMELOCK = 3600;

/** Maximum escrow timelock: 30 days */
export const APT_MAX_ESCROW_TIMELOCK = 30 * 24 * 3600;

/** Withdrawal refund delay: 24 hours */
export const APT_WITHDRAWAL_REFUND_DELAY = 24 * 3600;

/** Default ledger confirmations for finality */
export const APT_DEFAULT_LEDGER_CONFIRMATIONS = 6;

/** Aptos block time in ms (~160ms AptosBFT consensus) */
export const APT_BLOCK_TIME_MS = 160;

/** Aptos mainnet chain ID */
export const APTOS_CHAIN_ID = 1;

/** Aptos epoch duration (~2 hours) */
export const APTOS_EPOCH_DURATION_MS = 2 * 60 * 60 * 1000;

// =============================================================================
// ENUMS
// =============================================================================

export enum APTDepositStatus {
    PENDING = 0,
    VERIFIED = 1,
    COMPLETED = 2,
    FAILED = 3,
}

export enum APTWithdrawalStatus {
    PENDING = 0,
    PROCESSING = 1,
    COMPLETED = 2,
    REFUNDED = 3,
    FAILED = 4,
}

export enum APTEscrowStatus {
    ACTIVE = 0,
    FINISHED = 1,
    CANCELLED = 2,
}

export enum AptosBridgeOpType {
    COIN_TRANSFER = 0,
    RESOURCE_TRANSFER = 1,
    VALIDATOR_UPDATE = 2,
    EMERGENCY_OP = 3,
}

// =============================================================================
// TYPES
// =============================================================================

export interface APTDeposit {
    depositId: `0x${string}`;
    aptosTxHash: `0x${string}`;
    aptosSender: `0x${string}`; // 32-byte Aptos address
    evmRecipient: `0x${string}`;
    amountOctas: bigint;
    netAmountOctas: bigint;
    fee: bigint;
    status: APTDepositStatus;
    ledgerVersion: bigint;
    initiatedAt: bigint;
    completedAt: bigint;
}

export interface APTWithdrawal {
    withdrawalId: `0x${string}`;
    evmSender: `0x${string}`;
    aptosRecipient: `0x${string}`; // 32-byte Aptos address
    amountOctas: bigint;
    aptosTxHash: `0x${string}`;
    status: APTWithdrawalStatus;
    initiatedAt: bigint;
    completedAt: bigint;
}

export interface APTEscrow {
    escrowId: `0x${string}`;
    evmParty: `0x${string}`;
    aptosParty: `0x${string}`; // 32-byte Aptos address
    amountOctas: bigint;
    hashlock: `0x${string}`;
    preimage: `0x${string}`;
    finishAfter: bigint;
    cancelAfter: bigint;
    status: APTEscrowStatus;
    createdAt: bigint;
}

export interface AptosBridgeConfig {
    aptosBridgeContract: `0x${string}`;
    wrappedAPT: `0x${string}`;
    validatorOracle: `0x${string}`;
    minValidatorSignatures: bigint;
    requiredLedgerConfirmations: bigint;
    active: boolean;
}

export interface AptosLedgerInfo {
    ledgerVersion: bigint;
    transactionHash: `0x${string}`;
    stateRootHash: `0x${string}`;
    eventRootHash: `0x${string}`;
    epoch: bigint;
    round: bigint;
    timestamp: bigint;
    numTransactions: bigint;
    verified: boolean;
}

export interface ValidatorAttestation {
    validator: `0x${string}`; // EVM-mapped validator address
    signature: `0x${string}`;
}

export interface AptosStateProof {
    leafHash: `0x${string}`;
    proof: `0x${string}`[];
    index: bigint;
}

export interface AptosBridgeStats {
    totalDeposited: bigint;
    totalWithdrawn: bigint;
    totalEscrows: bigint;
    totalEscrowsFinished: bigint;
    totalEscrowsCancelled: bigint;
    accumulatedFees: bigint;
    latestLedgerVersion: bigint;
}

// =============================================================================
// CONVERSION UTILITIES
// =============================================================================

/**
 * Convert APT to Octas (smallest unit)
 * @param apt Amount in APT (supports decimals as string)
 * @returns Amount in Octas as bigint
 */
export function aptToOctas(apt: number | string): bigint {
    if (typeof apt === 'string') {
        const parts = apt.split('.');
        const whole = BigInt(parts[0]) * OCTAS_PER_APT;
        if (parts.length === 1) return whole;

        const decStr = parts[1].padEnd(8, '0').slice(0, 8);
        return whole + BigInt(decStr);
    }
    return aptToOctas(apt.toString());
}

/**
 * Convert Octas to APT string
 * @param octas Amount in Octas
 * @returns Formatted APT amount string (up to 8 decimals)
 */
export function octasToApt(octas: bigint): string {
    const whole = octas / OCTAS_PER_APT;
    const remainder = octas % OCTAS_PER_APT;

    if (remainder === 0n) return whole.toString();

    const fracStr = remainder.toString().padStart(8, '0').replace(/0+$/, '');
    return `${whole}.${fracStr}`;
}

/**
 * Format Octas as human-readable string with units
 * @param octas Amount in Octas
 * @returns e.g. "1.5 APT" or "500,000 Octas"
 */
export function formatAPTOctas(octas: bigint): string {
    if (octas >= OCTAS_PER_APT) {
        return `${octasToApt(octas)} APT`;
    }
    return `${octas.toLocaleString()} Octas`;
}

// =============================================================================
// VALIDATION UTILITIES
// =============================================================================

/**
 * Validate an Aptos address (32-byte hex, 0x-prefixed, 64 hex chars)
 * @param address Aptos address string
 * @returns True if the address format appears valid
 */
export function isValidAptosAddress(address: string): boolean {
    return /^0x[0-9a-fA-F]{64}$/.test(address);
}

/**
 * Validate a deposit amount is within bridge limits
 * @param amountOctas Amount in Octas
 * @returns Object with valid flag and error message if invalid
 */
export function validateAPTDepositAmount(amountOctas: bigint): {
    valid: boolean;
    error?: string;
} {
    if (amountOctas < APT_MIN_DEPOSIT_OCTAS) {
        return {
            valid: false,
            error: `Amount ${formatAPTOctas(amountOctas)} is below minimum deposit of ${formatAPTOctas(APT_MIN_DEPOSIT_OCTAS)}`,
        };
    }
    if (amountOctas > APT_MAX_DEPOSIT_OCTAS) {
        return {
            valid: false,
            error: `Amount ${formatAPTOctas(amountOctas)} exceeds maximum deposit of ${formatAPTOctas(APT_MAX_DEPOSIT_OCTAS)}`,
        };
    }
    return { valid: true };
}

// =============================================================================
// FEE CALCULATIONS
// =============================================================================

/**
 * Calculate the bridge fee for a given amount
 * @param amountOctas Gross amount in Octas
 * @returns Fee in Octas (0.04% by default)
 */
export function calculateAptosBridgeFee(amountOctas: bigint): bigint {
    return (amountOctas * APT_BRIDGE_FEE_BPS) / APT_BPS_DENOMINATOR;
}

/**
 * Calculate the net amount after bridge fee
 * @param amountOctas Gross amount in Octas
 * @returns Net amount in Octas
 */
export function calculateAptosNetAmount(amountOctas: bigint): bigint {
    return amountOctas - calculateAptosBridgeFee(amountOctas);
}

// =============================================================================
// ESCROW UTILITIES
// =============================================================================

/**
 * Generate a random preimage for HTLC escrow
 * @returns 32-byte hex preimage
 */
export function generateAptosPreimage(): `0x${string}` {
    const bytes = new Uint8Array(32);
    crypto.getRandomValues(bytes);
    return `0x${Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('')}`;
}

/**
 * Compute the SHA-256 hashlock from a preimage
 * @param preimage The 32-byte hex preimage
 * @returns SHA-256 hash of the preimage
 */
export async function computeAptosHashlock(preimage: `0x${string}`): Promise<`0x${string}`> {
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
export function validateAptosEscrowTimelocks(
    finishAfter: number,
    cancelAfter: number
): { valid: boolean; error?: string } {
    const now = Math.floor(Date.now() / 1000);

    if (finishAfter <= now) {
        return { valid: false, error: 'finishAfter must be in the future' };
    }

    const duration = cancelAfter - finishAfter;

    if (duration < APT_MIN_ESCROW_TIMELOCK) {
        return {
            valid: false,
            error: `Escrow duration ${duration}s is below minimum ${APT_MIN_ESCROW_TIMELOCK}s (1 hour)`,
        };
    }

    if (duration > APT_MAX_ESCROW_TIMELOCK) {
        return {
            valid: false,
            error: `Escrow duration ${duration}s exceeds maximum ${APT_MAX_ESCROW_TIMELOCK}s (30 days)`,
        };
    }

    return { valid: true };
}

// =============================================================================
// TIMING UTILITIES
// =============================================================================

/**
 * Estimate ledger finalization time
 * @param confirmations Number of ledger version confirmations (default: 6)
 * @returns Estimated time in milliseconds
 */
export function estimateAptosLedgerFinalityMs(confirmations?: number): number {
    const n = confirmations ?? APT_DEFAULT_LEDGER_CONFIRMATIONS;
    return n * APT_BLOCK_TIME_MS;
}

/**
 * Check if a withdrawal is eligible for refund
 * @param initiatedAt Timestamp when withdrawal was initiated (UNIX seconds)
 * @returns True if the refund delay (24 hours) has passed
 */
export function isAptosRefundEligible(initiatedAt: number): boolean {
    const now = Math.floor(Date.now() / 1000);
    return now >= initiatedAt + APT_WITHDRAWAL_REFUND_DELAY;
}

/**
 * Estimate remaining time until epoch change
 * @param epochStartMs Epoch start time in milliseconds
 * @returns Remaining time in milliseconds (0 if epoch should have ended)
 */
export function estimateRemainingEpochMs(epochStartMs: number): number {
    const now = Date.now();
    const epochEnd = epochStartMs + APTOS_EPOCH_DURATION_MS;
    return Math.max(0, epochEnd - now);
}

/**
 * Estimate time for a given number of AptosBFT consensus rounds
 * @param rounds Number of consensus rounds
 * @returns Estimated time in milliseconds
 */
export function estimateAptosConsensusTimeMs(rounds: number): number {
    return rounds * APT_BLOCK_TIME_MS;
}

// =============================================================================
// ABI FRAGMENTS
// =============================================================================

export const APTOS_BRIDGE_ABI = [
    // Configuration
    'function configure(address aptosBridgeContract, address wrappedAPT, address validatorOracle, uint256 minValidatorSignatures, uint256 requiredLedgerConfirmations) external',
    'function setTreasury(address _treasury) external',

    // Deposits (Aptos → Soul)
    'function initiateAPTDeposit(bytes32 aptosTxHash, bytes32 aptosSender, address evmRecipient, uint256 amountOctas, uint256 ledgerVersion, (bytes32 leafHash, bytes32[] proof, uint256 index) txProof, (address validator, bytes signature)[] attestations) external returns (bytes32)',
    'function completeAPTDeposit(bytes32 depositId) external',

    // Withdrawals (Soul → Aptos)
    'function initiateWithdrawal(bytes32 aptosRecipient, uint256 amountOctas) external returns (bytes32)',
    'function completeWithdrawal(bytes32 withdrawalId, bytes32 aptosTxHash, (bytes32 leafHash, bytes32[] proof, uint256 index) txProof, (address validator, bytes signature)[] attestations) external',
    'function refundWithdrawal(bytes32 withdrawalId) external',

    // Escrow (Atomic Swaps)
    'function createEscrow(bytes32 aptosParty, bytes32 hashlock, uint256 finishAfter, uint256 cancelAfter) external payable returns (bytes32)',
    'function finishEscrow(bytes32 escrowId, bytes32 preimage) external',
    'function cancelEscrow(bytes32 escrowId) external',

    // Privacy
    'function registerPrivateDeposit(bytes32 depositId, bytes32 commitment, bytes32 nullifier, bytes zkProof) external',

    // LedgerInfo Verification
    'function submitLedgerInfo(uint256 ledgerVersion, bytes32 transactionHash, bytes32 stateRootHash, bytes32 eventRootHash, uint256 epoch, uint256 round, uint256 timestamp, uint256 numTransactions, (address validator, bytes signature)[] attestations) external',

    // Views
    'function getDeposit(bytes32 depositId) external view returns (tuple)',
    'function getWithdrawal(bytes32 withdrawalId) external view returns (tuple)',
    'function getEscrow(bytes32 escrowId) external view returns (tuple)',
    'function getLedgerInfo(uint256 version) external view returns (tuple)',
    'function getUserDeposits(address user) external view returns (bytes32[])',
    'function getUserWithdrawals(address user) external view returns (bytes32[])',
    'function getUserEscrows(address user) external view returns (bytes32[])',
    'function getBridgeStats() external view returns (uint256, uint256, uint256, uint256, uint256, uint256, uint256)',

    // Admin
    'function pause() external',
    'function unpause() external',
    'function withdrawFees() external',

    // Constants
    'function APTOS_CHAIN_ID() view returns (uint256)',
    'function OCTAS_PER_APT() view returns (uint256)',
    'function MIN_DEPOSIT_OCTAS() view returns (uint256)',
    'function MAX_DEPOSIT_OCTAS() view returns (uint256)',
    'function BRIDGE_FEE_BPS() view returns (uint256)',
    'function WITHDRAWAL_REFUND_DELAY() view returns (uint256)',
    'function DEFAULT_LEDGER_CONFIRMATIONS() view returns (uint256)',

    // State
    'function depositNonce() view returns (uint256)',
    'function withdrawalNonce() view returns (uint256)',
    'function escrowNonce() view returns (uint256)',
    'function latestLedgerVersion() view returns (uint256)',
    'function currentEpoch() view returns (uint256)',
    'function totalDeposited() view returns (uint256)',
    'function totalWithdrawn() view returns (uint256)',
    'function accumulatedFees() view returns (uint256)',
    'function treasury() view returns (address)',
    'function usedAptosTxHashes(bytes32) view returns (bool)',
    'function usedNullifiers(bytes32) view returns (bool)',

    // Events
    'event BridgeConfigured(address indexed aptosBridgeContract, address wrappedAPT, address validatorOracle)',
    'event APTDepositInitiated(bytes32 indexed depositId, bytes32 indexed aptosTxHash, bytes32 aptosSender, address indexed evmRecipient, uint256 amountOctas)',
    'event APTDepositCompleted(bytes32 indexed depositId, address indexed evmRecipient, uint256 amountOctas)',
    'event APTWithdrawalInitiated(bytes32 indexed withdrawalId, address indexed evmSender, bytes32 aptosRecipient, uint256 amountOctas)',
    'event APTWithdrawalCompleted(bytes32 indexed withdrawalId, bytes32 aptosTxHash)',
    'event APTWithdrawalRefunded(bytes32 indexed withdrawalId, address indexed evmSender, uint256 amountOctas)',
    'event EscrowCreated(bytes32 indexed escrowId, address indexed evmParty, bytes32 aptosParty, uint256 amountOctas, bytes32 hashlock)',
    'event EscrowFinished(bytes32 indexed escrowId, bytes32 preimage)',
    'event EscrowCancelled(bytes32 indexed escrowId)',
    'event LedgerInfoVerified(uint256 indexed ledgerVersion, bytes32 transactionHash, uint256 epoch)',
    'event PrivateDepositRegistered(bytes32 indexed depositId, bytes32 commitment, bytes32 nullifier)',
    'event FeesWithdrawn(address indexed recipient, uint256 amount)',
] as const;

export const WRAPPED_APT_ABI = [
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
