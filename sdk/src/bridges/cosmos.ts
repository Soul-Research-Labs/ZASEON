/**
 * Soul Protocol - Cosmos Bridge SDK Module
 *
 * TypeScript utilities and types for interacting with the CosmosBridgeAdapter contract.
 * Provides Cosmos-specific helpers: uatom conversions, address validation,
 * fee calculations, Tendermint header utilities, and escrow helpers.
 *
 * Cosmos is a Layer 1 blockchain ecosystem built on the Cosmos SDK with Tendermint
 * BFT consensus providing ~6s block finality. It features IBC (Inter-Blockchain
 * Communication) for cross-chain transfers, IAVL+ tree state proofs, and
 * 6-decimal precision (uatom). Addresses use bech32 encoding with the "cosmos" prefix.
 *
 * @example
 * ```typescript
 * import { atomToUatom, uatomToAtom, calculateCosmosBridgeFee, COSMOS_BRIDGE_ABI } from './cosmos';
 *
 * const amount = atomToUatom(10); // 10_000_000n (10 ATOM in uatom)
 * const fee = calculateCosmosBridgeFee(amount); // 5_000n (0.05%)
 * ```
 */

// =============================================================================
// CONSTANTS
// =============================================================================

/** 1 ATOM = 1e6 uatom (6 decimals) */
export const UATOM_PER_ATOM = 1_000_000n;

/** Minimum deposit: 0.1 ATOM (100,000 uatom) */
export const MIN_DEPOSIT_UATOM = 100_000n;

/** Maximum deposit: 10,000,000 ATOM */
export const MAX_DEPOSIT_UATOM = 10_000_000n * UATOM_PER_ATOM;

/** Bridge fee: 5 BPS (0.05%) */
export const ATOM_BRIDGE_FEE_BPS = 5n;

/** BPS denominator */
export const ATOM_BPS_DENOMINATOR = 10_000n;

/** Minimum escrow timelock: 1 hour */
export const ATOM_MIN_ESCROW_TIMELOCK = 3600;

/** Maximum escrow timelock: 30 days */
export const ATOM_MAX_ESCROW_TIMELOCK = 30 * 24 * 3600;

/** Withdrawal refund delay: 24 hours */
export const ATOM_WITHDRAWAL_REFUND_DELAY = 24 * 3600;

/** Default block confirmations for Tendermint finality */
export const DEFAULT_BLOCK_CONFIRMATIONS = 1;

/** Cosmos block time in ms (~6000ms Tendermint BFT) */
export const ATOM_BLOCK_TIME_MS = 6000;

/** Cosmos Hub chain ID (SLIP-44 coin type) */
export const COSMOS_CHAIN_ID = 118;

/** Cosmos epoch duration: N/A (validator set changes per block, use 0) */
export const COSMOS_EPOCH_DURATION_MS = 0;

// =============================================================================
// ENUMS
// =============================================================================

export enum ATOMDepositStatus {
    PENDING = 0,
    VERIFIED = 1,
    COMPLETED = 2,
    FAILED = 3,
}

export enum ATOMWithdrawalStatus {
    PENDING = 0,
    PROCESSING = 1,
    COMPLETED = 2,
    REFUNDED = 3,
    FAILED = 4,
}

export enum ATOMEscrowStatus {
    ACTIVE = 0,
    FINISHED = 1,
    CANCELLED = 2,
}

export enum CosmosBridgeOpType {
    BANK_SEND = 0,
    IBC_TRANSFER = 1,
    VALIDATOR_SET_UPDATE = 2,
    EMERGENCY_OP = 3,
}

// =============================================================================
// TYPES
// =============================================================================

export interface ATOMDeposit {
    depositId: `0x${string}`;
    cosmosTxHash: `0x${string}`;
    cosmosSender: `0x${string}`; // 32-byte bech32-encoded address
    evmRecipient: `0x${string}`;
    amountUatom: bigint;
    netAmountUatom: bigint;
    fee: bigint;
    status: ATOMDepositStatus;
    blockHeight: bigint;
    initiatedAt: bigint;
    completedAt: bigint;
}

export interface ATOMWithdrawal {
    withdrawalId: `0x${string}`;
    evmSender: `0x${string}`;
    cosmosRecipient: `0x${string}`; // 32-byte bech32-encoded address
    amountUatom: bigint;
    cosmosTxHash: `0x${string}`;
    status: ATOMWithdrawalStatus;
    initiatedAt: bigint;
    completedAt: bigint;
}

export interface ATOMEscrow {
    escrowId: `0x${string}`;
    evmParty: `0x${string}`;
    cosmosParty: `0x${string}`; // 32-byte bech32-encoded address
    amountUatom: bigint;
    hashlock: `0x${string}`;
    preimage: `0x${string}`;
    finishAfter: bigint;
    cancelAfter: bigint;
    status: ATOMEscrowStatus;
    createdAt: bigint;
}

export interface CosmosBridgeConfig {
    cosmosBridgeContract: `0x${string}`;
    wrappedATOM: `0x${string}`;
    validatorOracle: `0x${string}`;
    minValidatorSignatures: bigint;
    requiredBlockConfirmations: bigint;
    active: boolean;
}

export interface TendermintHeader {
    height: bigint;
    blockHash: `0x${string}`;
    appHash: `0x${string}`;
    validatorsHash: `0x${string}`;
    timestamp: bigint;
    verified: boolean;
}

export interface IBCProof {
    merklePath: `0x${string}`[];
    commitmentRoot: `0x${string}`;
    value: `0x${string}`;
}

export interface ValidatorAttestation {
    validator: `0x${string}`; // EVM-mapped validator address
    signature: `0x${string}`;
}

export interface CosmosBridgeStats {
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
 * Convert ATOM to uatom (smallest unit)
 * @param atom Amount in ATOM (supports decimals as string)
 * @returns Amount in uatom as bigint
 */
export function atomToUatom(atom: number | string): bigint {
    if (typeof atom === 'string') {
        const parts = atom.split('.');
        const whole = BigInt(parts[0]) * UATOM_PER_ATOM;
        if (parts.length === 1) return whole;

        const decStr = parts[1].padEnd(6, '0').slice(0, 6);
        return whole + BigInt(decStr);
    }
    return atomToUatom(atom.toString());
}

/**
 * Convert uatom to ATOM string
 * @param uatom Amount in uatom
 * @returns Formatted ATOM amount string (up to 6 decimals)
 */
export function uatomToAtom(uatom: bigint): string {
    const whole = uatom / UATOM_PER_ATOM;
    const remainder = uatom % UATOM_PER_ATOM;

    if (remainder === 0n) return whole.toString();

    const fracStr = remainder.toString().padStart(6, '0').replace(/0+$/, '');
    return `${whole}.${fracStr}`;
}

/**
 * Format uatom as human-readable string with units
 * @param uatom Amount in uatom
 * @returns e.g. "1.5 ATOM" or "500,000 uatom"
 */
export function formatATOMUatom(uatom: bigint): string {
    if (uatom >= UATOM_PER_ATOM) {
        return `${uatomToAtom(uatom)} ATOM`;
    }
    return `${uatom.toLocaleString()} uatom`;
}

// =============================================================================
// VALIDATION UTILITIES
// =============================================================================

/**
 * Validate a Cosmos address (32-byte hex, 0x-prefixed, 64 hex chars)
 * @param address Cosmos address string (bytes32 encoded bech32)
 * @returns True if the address format appears valid
 */
export function isValidCosmosAddress(address: string): boolean {
    return /^0x[0-9a-fA-F]{64}$/.test(address);
}

/**
 * Validate a deposit amount is within bridge limits
 * @param amountUatom Amount in uatom
 * @returns Object with valid flag and error message if invalid
 */
export function validateATOMDepositAmount(amountUatom: bigint): {
    valid: boolean;
    error?: string;
} {
    if (amountUatom < MIN_DEPOSIT_UATOM) {
        return {
            valid: false,
            error: `Amount ${formatATOMUatom(amountUatom)} is below minimum deposit of ${formatATOMUatom(MIN_DEPOSIT_UATOM)}`,
        };
    }
    if (amountUatom > MAX_DEPOSIT_UATOM) {
        return {
            valid: false,
            error: `Amount ${formatATOMUatom(amountUatom)} exceeds maximum deposit of ${formatATOMUatom(MAX_DEPOSIT_UATOM)}`,
        };
    }
    return { valid: true };
}

// =============================================================================
// FEE CALCULATIONS
// =============================================================================

/**
 * Calculate the bridge fee for a given amount
 * @param amountUatom Gross amount in uatom
 * @returns Fee in uatom (0.05% by default)
 */
export function calculateCosmosBridgeFee(amountUatom: bigint): bigint {
    return (amountUatom * ATOM_BRIDGE_FEE_BPS) / ATOM_BPS_DENOMINATOR;
}

/**
 * Calculate the net amount after bridge fee
 * @param amountUatom Gross amount in uatom
 * @returns Net amount in uatom
 */
export function calculateCosmosNetAmount(amountUatom: bigint): bigint {
    return amountUatom - calculateCosmosBridgeFee(amountUatom);
}

// =============================================================================
// ESCROW UTILITIES
// =============================================================================

/**
 * Generate a random preimage for HTLC escrow
 * @returns 32-byte hex preimage
 */
export function generateCosmosPreimage(): `0x${string}` {
    const bytes = new Uint8Array(32);
    crypto.getRandomValues(bytes);
    return `0x${Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('')}`;
}

/**
 * Compute the SHA-256 hashlock from a preimage
 * @param preimage The 32-byte hex preimage
 * @returns SHA-256 hash of the preimage
 */
export async function computeCosmosHashlock(preimage: `0x${string}`): Promise<`0x${string}`> {
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
export function validateCosmosEscrowTimelocks(
    finishAfter: number,
    cancelAfter: number
): { valid: boolean; error?: string } {
    const now = Math.floor(Date.now() / 1000);

    if (finishAfter <= now) {
        return { valid: false, error: 'finishAfter must be in the future' };
    }

    const duration = cancelAfter - finishAfter;

    if (duration < ATOM_MIN_ESCROW_TIMELOCK) {
        return {
            valid: false,
            error: `Escrow duration ${duration}s is below minimum ${ATOM_MIN_ESCROW_TIMELOCK}s (1 hour)`,
        };
    }

    if (duration > ATOM_MAX_ESCROW_TIMELOCK) {
        return {
            valid: false,
            error: `Escrow duration ${duration}s exceeds maximum ${ATOM_MAX_ESCROW_TIMELOCK}s (30 days)`,
        };
    }

    return { valid: true };
}

// =============================================================================
// TIMING UTILITIES
// =============================================================================

/**
 * Estimate Tendermint finality time
 * @param confirmations Number of block confirmations (default: 1)
 * @returns Estimated time in milliseconds
 */
export function estimateCosmosFinalityMs(confirmations?: number): number {
    const n = confirmations ?? DEFAULT_BLOCK_CONFIRMATIONS;
    return n * ATOM_BLOCK_TIME_MS;
}

/**
 * Check if a withdrawal is eligible for refund
 * @param initiatedAt Timestamp when withdrawal was initiated (UNIX seconds)
 * @returns True if the refund delay (24 hours) has passed
 */
export function isCosmosRefundEligible(initiatedAt: number): boolean {
    const now = Math.floor(Date.now() / 1000);
    return now >= initiatedAt + ATOM_WITHDRAWAL_REFUND_DELAY;
}

/**
 * Estimate time for a given number of Tendermint blocks
 * @param blocks Number of blocks
 * @returns Estimated time in milliseconds
 */
export function estimateCosmosBlockTimeMs(blocks: number): number {
    return blocks * ATOM_BLOCK_TIME_MS;
}

/**
 * Estimate IBC packet relay time (typically 1-3 blocks on each chain)
 * @param sourceBlocks Number of source chain blocks for commitment
 * @param destBlocks Number of destination chain blocks for acknowledgement
 * @returns Estimated total relay time in milliseconds
 */
export function estimateIBCRelayTimeMs(sourceBlocks: number, destBlocks: number): number {
    return (sourceBlocks + destBlocks) * ATOM_BLOCK_TIME_MS;
}

// =============================================================================
// ABI FRAGMENTS
// =============================================================================

export const COSMOS_BRIDGE_ABI = [
    // Configuration
    'function configure(address cosmosBridgeContract, address wrappedATOM, address validatorOracle, uint256 minValidatorSignatures, uint256 requiredBlockConfirmations) external',
    'function setTreasury(address _treasury) external',

    // Tendermint Header Verification
    'function submitTendermintHeader(uint256 height, bytes32 blockHash, bytes32 appHash, bytes32 validatorsHash, uint256 timestamp, (address validator, bytes signature)[] attestations) external',

    // Deposits (Cosmos → Soul)
    'function initiateATOMDeposit(bytes32 cosmosTxHash, bytes32 cosmosSender, address evmRecipient, uint256 amountUatom, uint256 blockHeight, (bytes32[] merklePath, bytes32 commitmentRoot, bytes32 value) ibcProof, (address validator, bytes signature)[] attestations) external returns (bytes32)',
    'function completeATOMDeposit(bytes32 depositId) external',

    // Withdrawals (Soul → Cosmos)
    'function initiateWithdrawal(bytes32 cosmosRecipient, uint256 amountUatom) external returns (bytes32)',
    'function completeWithdrawal(bytes32 withdrawalId, bytes32 cosmosTxHash, (bytes32[] merklePath, bytes32 commitmentRoot, bytes32 value) ibcProof, (address validator, bytes signature)[] attestations) external',
    'function refundWithdrawal(bytes32 withdrawalId) external',

    // Escrow (Atomic Swaps)
    'function createEscrow(bytes32 cosmosParty, bytes32 hashlock, uint256 finishAfter, uint256 cancelAfter) external payable returns (bytes32)',
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
    'function getTendermintHeader(bytes32 blockHash) external view returns (tuple)',
    'function getUserDeposits(address user) external view returns (bytes32[])',
    'function getUserWithdrawals(address user) external view returns (bytes32[])',
    'function getUserEscrows(address user) external view returns (bytes32[])',
    'function getBridgeStats() external view returns (uint256, uint256, uint256, uint256, uint256, uint256, uint256)',

    // Constants
    'function COSMOS_CHAIN_ID() view returns (uint256)',
    'function UATOM_PER_ATOM() view returns (uint256)',
    'function MIN_DEPOSIT_UATOM() view returns (uint256)',
    'function MAX_DEPOSIT_UATOM() view returns (uint256)',
    'function BRIDGE_FEE_BPS() view returns (uint256)',
    'function WITHDRAWAL_REFUND_DELAY() view returns (uint256)',
    'function DEFAULT_BLOCK_CONFIRMATIONS() view returns (uint256)',

    // State
    'function depositNonce() view returns (uint256)',
    'function withdrawalNonce() view returns (uint256)',
    'function escrowNonce() view returns (uint256)',
    'function latestBlockHeight() view returns (uint256)',
    'function currentValidatorsHash() view returns (bytes32)',
    'function totalDeposited() view returns (uint256)',
    'function totalWithdrawn() view returns (uint256)',
    'function accumulatedFees() view returns (uint256)',
    'function treasury() view returns (address)',
    'function usedCosmosTxHashes(bytes32) view returns (bool)',
    'function usedNullifiers(bytes32) view returns (bool)',

    // Events
    'event BridgeConfigured(address indexed cosmosBridgeContract, address wrappedATOM, address validatorOracle)',
    'event TendermintHeaderSubmitted(uint256 indexed height, bytes32 indexed blockHash, bytes32 appHash, bytes32 validatorsHash)',
    'event ATOMDepositInitiated(bytes32 indexed depositId, bytes32 indexed cosmosTxHash, bytes32 cosmosSender, address indexed evmRecipient, uint256 amountUatom)',
    'event ATOMDepositCompleted(bytes32 indexed depositId, address indexed evmRecipient, uint256 amountUatom)',
    'event ATOMWithdrawalInitiated(bytes32 indexed withdrawalId, address indexed evmSender, bytes32 cosmosRecipient, uint256 amountUatom)',
    'event ATOMWithdrawalCompleted(bytes32 indexed withdrawalId, bytes32 cosmosTxHash)',
    'event ATOMWithdrawalRefunded(bytes32 indexed withdrawalId, address indexed evmSender, uint256 amountUatom)',
    'event EscrowCreated(bytes32 indexed escrowId, address indexed evmParty, bytes32 cosmosParty, uint256 amountUatom, bytes32 hashlock)',
    'event EscrowFinished(bytes32 indexed escrowId, bytes32 preimage)',
    'event EscrowCancelled(bytes32 indexed escrowId)',
    'event PrivateDepositRegistered(bytes32 indexed depositId, bytes32 commitment, bytes32 nullifier)',
    'event FeesWithdrawn(address indexed recipient, uint256 amount)',
] as const;

export const WRAPPED_ATOM_ABI = [
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
