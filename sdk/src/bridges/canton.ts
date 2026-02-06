/**
 * Soul Protocol - Canton Network Bridge SDK Module
 *
 * TypeScript utilities and types for interacting with the CantonBridgeAdapter contract.
 * Provides Canton-specific helpers: microcanton conversions, party ID validation,
 * fee calculations, Merkle proof construction, and escrow utilities.
 *
 * Canton Network is Digital Asset's privacy-enabled enterprise blockchain built on
 * Daml and the Canton Protocol. It uses a Global Synchronizer for cross-domain
 * coordination with sub-transaction privacy, mediator nodes, and sequencer nodes.
 *
 * @example
 * ```typescript
 * import { cantonToMicrocanton, microcantonToCanton, calculateCantonBridgeFee, CANTON_BRIDGE_ABI } from './canton';
 *
 * const amount = cantonToMicrocanton(10); // 10_000_000n (10 CANTON in microcanton)
 * const fee = calculateCantonBridgeFee(amount); // 5_000n (0.05%)
 * ```
 */

// =============================================================================
// CONSTANTS
// =============================================================================

/** 1 CANTON = 1e6 microcanton (6 decimals) */
export const MICROCANTON_PER_CANTON = 1_000_000n;

/** Minimum deposit: 0.1 CANTON (100,000 microcanton) */
export const CANTON_MIN_DEPOSIT_MICROCANTON = MICROCANTON_PER_CANTON / 10n;

/** Maximum deposit: 10,000,000 CANTON */
export const CANTON_MAX_DEPOSIT_MICROCANTON = 10_000_000n * MICROCANTON_PER_CANTON;

/** Bridge fee: 5 BPS (0.05%) — institutional-grade lowest fee */
export const CANTON_BRIDGE_FEE_BPS = 5n;

/** BPS denominator */
export const CANTON_BPS_DENOMINATOR = 10_000n;

/** Minimum escrow timelock: 2 hours */
export const CANTON_MIN_ESCROW_TIMELOCK = 2 * 3600;

/** Maximum escrow timelock: 60 days */
export const CANTON_MAX_ESCROW_TIMELOCK = 60 * 24 * 3600;

/** Withdrawal refund delay: 72 hours */
export const CANTON_WITHDRAWAL_REFUND_DELAY = 72 * 3600;

/** Default round confirmations (synchronizer rounds, not blocks) */
export const CANTON_DEFAULT_ROUND_CONFIRMATIONS = 5;

/** Canton synchronizer round time in ms (~2000ms / 2s) */
export const CANTON_ROUND_TIME_MS = 2000;

/** Canton chain ID (canton-global-1 EVM mapping) */
export const CANTON_CHAIN_ID = 510;

/** Number of active mediators (~20 on Global Synchronizer mainnet) */
export const CANTON_ACTIVE_MEDIATORS = 20;

/** Mediator supermajority: 2/3+1 = 14 of 20 */
export const CANTON_SUPERMAJORITY = 14;

// =============================================================================
// ENUMS
// =============================================================================

export enum CANTONDepositStatus {
    PENDING = 0,
    VERIFIED = 1,
    COMPLETED = 2,
    FAILED = 3,
}

export enum CANTONWithdrawalStatus {
    PENDING = 0,
    PROCESSING = 1,
    COMPLETED = 2,
    REFUNDED = 3,
    FAILED = 4,
}

export enum CANTONEscrowStatus {
    ACTIVE = 0,
    FINISHED = 1,
    CANCELLED = 2,
}

export enum CantonTxType {
    TRANSFER = 0,
    DAML_EXERCISE = 1,
    DOMAIN_TRANSFER = 2,
    CROSS_CHAIN = 3,
}

// =============================================================================
// TYPES
// =============================================================================

export interface CANTONDeposit {
    depositId: `0x${string}`;
    cantonTxHash: `0x${string}`;
    cantonSender: `0x${string}`;
    evmRecipient: `0x${string}`;
    amountMicrocanton: bigint;
    netAmountMicrocanton: bigint;
    fee: bigint;
    status: CANTONDepositStatus;
    roundNumber: bigint;
    initiatedAt: bigint;
    completedAt: bigint;
}

export interface CANTONWithdrawal {
    withdrawalId: `0x${string}`;
    evmSender: `0x${string}`;
    cantonRecipient: `0x${string}`;
    amountMicrocanton: bigint;
    cantonTxHash: `0x${string}`;
    status: CANTONWithdrawalStatus;
    initiatedAt: bigint;
    completedAt: bigint;
}

export interface CANTONEscrow {
    escrowId: `0x${string}`;
    evmParty: `0x${string}`;
    cantonParty: `0x${string}`;
    amountMicrocanton: bigint;
    hashlock: `0x${string}`;
    preimage: `0x${string}`;
    finishAfter: bigint;
    cancelAfter: bigint;
    status: CANTONEscrowStatus;
    createdAt: bigint;
}

export interface CantonBridgeConfig {
    cantonBridgeContract: `0x${string}`;
    wrappedCANTON: `0x${string}`;
    mediatorOracle: `0x${string}`;
    minMediatorSignatures: bigint;
    requiredRoundConfirmations: bigint;
    active: boolean;
}

export interface SynchronizerRoundHeader {
    roundNumber: bigint;
    roundHash: `0x${string}`;
    parentHash: `0x${string}`;
    transactionsRoot: `0x${string}`;
    stateRoot: `0x${string}`;
    mediatorSetHash: `0x${string}`;
    domainTopologyHash: `0x${string}`;
    roundTime: bigint;
    finalized: boolean;
}

export interface MediatorAttestation {
    mediator: `0x${string}`;
    signature: `0x${string}`;
}

export interface CantonMerkleProof {
    leafHash: `0x${string}`;
    proof: `0x${string}`[];
    index: bigint;
}

export interface CantonBridgeStats {
    totalDeposited: bigint;
    totalWithdrawn: bigint;
    totalEscrows: bigint;
    totalEscrowsFinished: bigint;
    totalEscrowsCancelled: bigint;
    accumulatedFees: bigint;
    latestRoundNumber: bigint;
}

// =============================================================================
// CONVERSION UTILITIES
// =============================================================================

/**
 * Convert CANTON to microcanton (smallest unit)
 * @param canton Amount in CANTON (supports decimals as string)
 * @returns Amount in microcanton as bigint
 */
export function cantonToMicrocanton(canton: number | string): bigint {
    if (typeof canton === 'string') {
        const parts = canton.split('.');
        const whole = BigInt(parts[0]) * MICROCANTON_PER_CANTON;
        if (parts.length === 1) return whole;

        const decStr = parts[1].padEnd(6, '0').slice(0, 6);
        return whole + BigInt(decStr);
    }
    return cantonToMicrocanton(canton.toString());
}

/**
 * Convert microcanton to CANTON string
 * @param microcanton Amount in microcanton
 * @returns Formatted CANTON amount string (up to 6 decimals)
 */
export function microcantonToCanton(microcanton: bigint): string {
    const whole = microcanton / MICROCANTON_PER_CANTON;
    const remainder = microcanton % MICROCANTON_PER_CANTON;

    if (remainder === 0n) return whole.toString();

    const fracStr = remainder.toString().padStart(6, '0').replace(/0+$/, '');
    return `${whole}.${fracStr}`;
}

/**
 * Format microcanton as human-readable string with units
 * @param microcanton Amount in microcanton
 * @returns e.g. "1.5 CANTON" or "500,000 microcanton"
 */
export function formatCANTONMicrocanton(microcanton: bigint): string {
    if (microcanton >= MICROCANTON_PER_CANTON) {
        return `${microcantonToCanton(microcanton)} CANTON`;
    }
    return `${microcanton.toLocaleString()} microcanton`;
}

// =============================================================================
// VALIDATION UTILITIES
// =============================================================================

/**
 * Validate a Canton party ID (party::domain format)
 * Canton uses party IDs in the format "party::domain" where both segments
 * are alphanumeric identifiers separated by a double colon.
 * @param partyId Canton party ID string
 * @returns True if the party ID format appears valid
 */
export function isValidCantonPartyId(partyId: string): boolean {
    // Canton party IDs follow the format: identifier::domain-identifier
    // Both segments are alphanumeric with hyphens/underscores
    return /^[a-zA-Z0-9_-]+::[a-zA-Z0-9._-]+$/.test(partyId);
}

/**
 * Validate an EVM address (for the EVM side of the bridge)
 * @param address EVM address string
 * @returns True if the address format is valid
 */
export function isValidCantonEVMAddress(address: string): boolean {
    return /^0x[0-9a-fA-F]{40}$/.test(address);
}

/**
 * Validate a deposit amount is within bridge limits
 * @param amountMicrocanton Amount in microcanton
 * @returns Object with valid flag and error message if invalid
 */
export function validateCANTONDepositAmount(amountMicrocanton: bigint): {
    valid: boolean;
    error?: string;
} {
    if (amountMicrocanton < CANTON_MIN_DEPOSIT_MICROCANTON) {
        return {
            valid: false,
            error: `Amount ${formatCANTONMicrocanton(amountMicrocanton)} is below minimum deposit of ${formatCANTONMicrocanton(CANTON_MIN_DEPOSIT_MICROCANTON)}`,
        };
    }
    if (amountMicrocanton > CANTON_MAX_DEPOSIT_MICROCANTON) {
        return {
            valid: false,
            error: `Amount ${formatCANTONMicrocanton(amountMicrocanton)} exceeds maximum deposit of ${formatCANTONMicrocanton(CANTON_MAX_DEPOSIT_MICROCANTON)}`,
        };
    }
    return { valid: true };
}

// =============================================================================
// FEE CALCULATIONS
// =============================================================================

/**
 * Calculate the bridge fee for a given amount
 * @param amountMicrocanton Gross amount in microcanton
 * @returns Fee in microcanton (0.05% by default)
 */
export function calculateCantonBridgeFee(amountMicrocanton: bigint): bigint {
    return (amountMicrocanton * CANTON_BRIDGE_FEE_BPS) / CANTON_BPS_DENOMINATOR;
}

/**
 * Calculate the net amount after bridge fee
 * @param amountMicrocanton Gross amount in microcanton
 * @returns Net amount in microcanton
 */
export function calculateCantonNetAmount(amountMicrocanton: bigint): bigint {
    return amountMicrocanton - calculateCantonBridgeFee(amountMicrocanton);
}

// =============================================================================
// ESCROW UTILITIES
// =============================================================================

/**
 * Generate a random preimage for HTLC escrow
 * @returns 32-byte hex preimage
 */
export function generateCantonPreimage(): `0x${string}` {
    const bytes = new Uint8Array(32);
    crypto.getRandomValues(bytes);
    return `0x${Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('')}`;
}

/**
 * Compute the SHA-256 hashlock from a preimage
 * @param preimage The 32-byte hex preimage
 * @returns SHA-256 hash of the preimage
 */
export async function computeCantonHashlock(preimage: `0x${string}`): Promise<`0x${string}`> {
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
export function validateCantonEscrowTimelocks(
    finishAfter: number,
    cancelAfter: number
): { valid: boolean; error?: string } {
    const now = Math.floor(Date.now() / 1000);

    if (finishAfter <= now) {
        return { valid: false, error: 'finishAfter must be in the future' };
    }

    const duration = cancelAfter - finishAfter;

    if (duration < CANTON_MIN_ESCROW_TIMELOCK) {
        return {
            valid: false,
            error: `Escrow duration ${duration}s is below minimum ${CANTON_MIN_ESCROW_TIMELOCK}s (2 hours)`,
        };
    }

    if (duration > CANTON_MAX_ESCROW_TIMELOCK) {
        return {
            valid: false,
            error: `Escrow duration ${duration}s exceeds maximum ${CANTON_MAX_ESCROW_TIMELOCK}s (60 days)`,
        };
    }

    return { valid: true };
}

// =============================================================================
// TIMING UTILITIES
// =============================================================================

/**
 * Estimate confirmation time for a given number of round confirmations
 * @param roundConfirmations Number of synchronizer round confirmations required
 * @returns Estimated time in seconds
 */
export function estimateCantonConfirmationTime(
    roundConfirmations: number = CANTON_DEFAULT_ROUND_CONFIRMATIONS
): number {
    return Math.ceil((roundConfirmations * CANTON_ROUND_TIME_MS) / 1000);
}

/**
 * Check if a withdrawal is eligible for refund
 * @param initiatedAt Timestamp when withdrawal was initiated (UNIX seconds)
 * @returns True if the refund delay (72h) has passed
 */
export function isCantonRefundEligible(initiatedAt: number): boolean {
    const now = Math.floor(Date.now() / 1000);
    return now >= initiatedAt + CANTON_WITHDRAWAL_REFUND_DELAY;
}

/**
 * Estimate synchronizer finality time in milliseconds
 * @returns Estimated finality time (~10s for 5 rounds)
 */
export function estimateCantonFinalityMs(): number {
    return CANTON_DEFAULT_ROUND_CONFIRMATIONS * CANTON_ROUND_TIME_MS;
}

// =============================================================================
// ABI FRAGMENTS
// =============================================================================

export const CANTON_BRIDGE_ABI = [
    // Configuration
    'function configure(address cantonBridgeContract, address wrappedCANTON, address mediatorOracle, uint256 minMediatorSignatures, uint256 requiredRoundConfirmations) external',
    'function setTreasury(address _treasury) external',

    // Deposits (Canton → Soul)
    'function initiateCANTONDeposit(bytes32 cantonTxHash, address cantonSender, address evmRecipient, uint256 amountMicrocanton, uint256 roundNumber, (bytes32 leafHash, bytes32[] proof, uint256 index) txProof, (address mediator, bytes signature)[] attestations) external returns (bytes32)',
    'function completeCANTONDeposit(bytes32 depositId) external',

    // Withdrawals (Soul → Canton)
    'function initiateWithdrawal(address cantonRecipient, uint256 amountMicrocanton) external returns (bytes32)',
    'function completeWithdrawal(bytes32 withdrawalId, bytes32 cantonTxHash, (bytes32 leafHash, bytes32[] proof, uint256 index) txProof, (address mediator, bytes signature)[] attestations) external',
    'function refundWithdrawal(bytes32 withdrawalId) external',

    // Escrow (Atomic Swaps)
    'function createEscrow(address cantonParty, bytes32 hashlock, uint256 finishAfter, uint256 cancelAfter) external payable returns (bytes32)',
    'function finishEscrow(bytes32 escrowId, bytes32 preimage) external',
    'function cancelEscrow(bytes32 escrowId) external',

    // Privacy
    'function registerPrivateDeposit(bytes32 depositId, bytes32 commitment, bytes32 nullifier, bytes zkProof) external',

    // Synchronizer Round Headers (includes mediatorSetHash + domainTopologyHash)
    'function submitRoundHeader(uint256 roundNumber, bytes32 roundHash, bytes32 parentHash, bytes32 transactionsRoot, bytes32 stateRoot, bytes32 mediatorSetHash, bytes32 domainTopologyHash, uint256 roundTime, (address mediator, bytes signature)[] attestations) external',

    // Views
    'function getDeposit(bytes32 depositId) external view returns (tuple)',
    'function getWithdrawal(bytes32 withdrawalId) external view returns (tuple)',
    'function getEscrow(bytes32 escrowId) external view returns (tuple)',
    'function getRoundHeader(uint256 roundNumber) external view returns (tuple)',
    'function getUserDeposits(address user) external view returns (bytes32[])',
    'function getUserWithdrawals(address user) external view returns (bytes32[])',
    'function getUserEscrows(address user) external view returns (bytes32[])',
    'function getBridgeStats() external view returns (uint256, uint256, uint256, uint256, uint256, uint256, uint256)',

    // Admin
    'function pause() external',
    'function unpause() external',
    'function withdrawFees() external',

    // Constants
    'function CANTON_CHAIN_ID() view returns (uint256)',
    'function MICROCANTON_PER_CANTON() view returns (uint256)',
    'function MIN_DEPOSIT_MICROCANTON() view returns (uint256)',
    'function MAX_DEPOSIT_MICROCANTON() view returns (uint256)',
    'function BRIDGE_FEE_BPS() view returns (uint256)',
    'function WITHDRAWAL_REFUND_DELAY() view returns (uint256)',
    'function DEFAULT_ROUND_CONFIRMATIONS() view returns (uint256)',

    // State
    'function depositNonce() view returns (uint256)',
    'function withdrawalNonce() view returns (uint256)',
    'function escrowNonce() view returns (uint256)',
    'function latestRoundNumber() view returns (uint256)',
    'function totalDeposited() view returns (uint256)',
    'function totalWithdrawn() view returns (uint256)',
    'function accumulatedFees() view returns (uint256)',
    'function treasury() view returns (address)',
    'function usedCantonTxHashes(bytes32) view returns (bool)',
    'function usedNullifiers(bytes32) view returns (bool)',

    // Events
    'event BridgeConfigured(address indexed cantonBridgeContract, address wrappedCANTON, address mediatorOracle)',
    'event CANTONDepositInitiated(bytes32 indexed depositId, bytes32 indexed cantonTxHash, address cantonSender, address indexed evmRecipient, uint256 amountMicrocanton)',
    'event CANTONDepositCompleted(bytes32 indexed depositId, address indexed evmRecipient, uint256 amountMicrocanton)',
    'event CANTONWithdrawalInitiated(bytes32 indexed withdrawalId, address indexed evmSender, address cantonRecipient, uint256 amountMicrocanton)',
    'event CANTONWithdrawalCompleted(bytes32 indexed withdrawalId, bytes32 cantonTxHash)',
    'event CANTONWithdrawalRefunded(bytes32 indexed withdrawalId, address indexed evmSender, uint256 amountMicrocanton)',
    'event EscrowCreated(bytes32 indexed escrowId, address indexed evmParty, address cantonParty, uint256 amountMicrocanton, bytes32 hashlock)',
    'event EscrowFinished(bytes32 indexed escrowId, bytes32 preimage)',
    'event EscrowCancelled(bytes32 indexed escrowId)',
    'event RoundHeaderSubmitted(uint256 indexed roundNumber, bytes32 roundHash)',
    'event PrivateDepositRegistered(bytes32 indexed depositId, bytes32 commitment, bytes32 nullifier)',
    'event FeesWithdrawn(address indexed recipient, uint256 amount)',
] as const;

export const WRAPPED_CANTON_ABI = [
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
