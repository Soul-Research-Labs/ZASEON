/**
 * @fileoverview XRP Ledger bridge utilities for Soul SDK
 * @module bridges/xrpl
 */

import { keccak256, toBytes, toHex, sha256, encodePacked, type Address, type Hash } from 'viem';

/*//////////////////////////////////////////////////////////////
                            CONSTANTS
//////////////////////////////////////////////////////////////*/

/** XRPL "chain ID" (keccak256 of "XRPLedger") */
export const XRPL_CHAIN_ID = BigInt(keccak256(toBytes('XRPLedger')));

/** Drops per XRP (1 XRP = 1,000,000 drops) */
export const DROPS_PER_XRP = 1_000_000n;

/** Minimum deposit in drops (10 XRP) */
export const MIN_DEPOSIT_DROPS = 10n * DROPS_PER_XRP;

/** Maximum deposit in drops (10M XRP) */
export const MAX_DEPOSIT_DROPS = 10_000_000n * DROPS_PER_XRP;

/** Default escrow timelock (24 hours in seconds) */
export const DEFAULT_ESCROW_TIMELOCK = 86400;

/** Minimum escrow timelock (1 hour) */
export const MIN_ESCROW_TIMELOCK = 3600;

/** Maximum escrow timelock (30 days) */
export const MAX_ESCROW_TIMELOCK = 2_592_000;

/** Bridge fee in basis points (0.25%) */
export const BRIDGE_FEE_BPS = 25;

/** Required ledger confirmations */
export const REQUIRED_LEDGER_CONFIRMATIONS = 32;

/** Withdrawal refund delay (48 hours) */
export const WITHDRAWAL_REFUND_DELAY = 172_800;

/** Ripple epoch offset (seconds between Unix epoch and Ripple epoch) */
export const RIPPLE_EPOCH_OFFSET = 946684800;

/*//////////////////////////////////////////////////////////////
                              TYPES
//////////////////////////////////////////////////////////////*/

export type XRPLNetwork = 'mainnet' | 'testnet' | 'devnet';

export enum DepositStatus {
  PENDING = 0,
  VERIFIED = 1,
  COMPLETED = 2,
  FAILED = 3,
}

export enum WithdrawalStatus {
  PENDING = 0,
  PROCESSING = 1,
  COMPLETED = 2,
  REFUNDED = 3,
  FAILED = 4,
}

export enum EscrowStatus {
  ACTIVE = 0,
  FINISHED = 1,
  CANCELLED = 2,
}

export interface XRPDeposit {
  depositId: Hash;
  xrplTxHash: Hash;
  xrplSender: `0x${string}`;
  evmRecipient: Address;
  amountDrops: bigint;
  netAmountDrops: bigint;
  fee: bigint;
  destinationTag: Hash;
  status: DepositStatus;
  ledgerIndex: bigint;
  initiatedAt: number;
  completedAt?: number;
}

export interface XRPWithdrawal {
  withdrawalId: Hash;
  evmSender: Address;
  xrplRecipient: `0x${string}`;
  amountDrops: bigint;
  xrplTxHash?: Hash;
  status: WithdrawalStatus;
  initiatedAt: number;
  completedAt?: number;
}

export interface XRPLEscrow {
  escrowId: Hash;
  evmParty: Address;
  xrplParty: `0x${string}`;
  amountDrops: bigint;
  condition: Hash;
  fulfillment?: Hash;
  finishAfter: number;
  cancelAfter: number;
  xrplEscrowTxHash?: Hash;
  status: EscrowStatus;
  createdAt: number;
}

export interface ValidatorAttestation {
  validatorPubKey: Hash;
  signature: `0x${string}`;
}

export interface SHAMapProof {
  leafHash: Hash;
  innerNodes: Hash[];
  nodeTypes: number[];
  branchKeys: Hash[];
}

export interface LedgerHeader {
  ledgerIndex: bigint;
  ledgerHash: Hash;
  parentHash: Hash;
  transactionHash: Hash;
  accountStateHash: Hash;
  closeTime: number;
  validated: boolean;
}

export interface BridgeConfig {
  xrplMultisigAccount: `0x${string}`;
  wrappedXRP: Address;
  validatorOracle: Address;
  minSignatures: bigint;
  requiredLedgerConfirmations: bigint;
  active: boolean;
}

export interface BridgeStats {
  totalDeposited: bigint;
  totalWithdrawn: bigint;
  totalEscrows: bigint;
  totalEscrowsFinished: bigint;
  totalEscrowsCancelled: bigint;
  accumulatedFees: bigint;
  latestLedgerIndex: bigint;
}

/*//////////////////////////////////////////////////////////////
                      UTILITY FUNCTIONS
//////////////////////////////////////////////////////////////*/

/**
 * Convert XRP to drops
 */
export function xrpToDrops(xrp: number): bigint {
  return BigInt(Math.floor(xrp * Number(DROPS_PER_XRP)));
}

/**
 * Convert drops to XRP
 */
export function dropsToXrp(drops: bigint): number {
  return Number(drops) / Number(DROPS_PER_XRP);
}

/**
 * Validate XRPL classic address format (r-address)
 * @param address XRPL classic address starting with 'r'
 * @returns Whether the address format is valid
 */
export function isValidXRPLAddress(address: string): boolean {
  // XRPL addresses are base58 encoded, starting with 'r', 25-35 chars
  return /^r[1-9A-HJ-NP-Za-km-z]{24,34}$/.test(address);
}

/**
 * Validate XRPL transaction hash format
 * @param hash 64-char hex string
 */
export function isValidXRPLTxHash(hash: string): boolean {
  return /^[A-Fa-f0-9]{64}$/.test(hash.replace('0x', ''));
}

/**
 * Convert XRPL address to bytes20 hex
 * @param address Raw hex bytes (strip r-address encoding)
 */
export function xrplAddressToBytes20(hexAddress: string): `0x${string}` {
  const clean = hexAddress.replace('0x', '');
  if (clean.length !== 40) {
    throw new Error('Invalid XRPL address hex (expected 20 bytes / 40 hex chars)');
  }
  return `0x${clean}` as `0x${string}`;
}

/**
 * Convert XRPL tx hash to bytes32
 */
export function xrplTxHashToBytes32(txHash: string): Hash {
  const clean = txHash.replace('0x', '');
  if (clean.length !== 64) {
    throw new Error('Invalid XRPL tx hash (expected 32 bytes / 64 hex chars)');
  }
  return `0x${clean}` as Hash;
}

/**
 * Calculate bridge fee for a given amount in drops
 */
export function calculateBridgeFee(amountDrops: bigint, feeBps: number = BRIDGE_FEE_BPS): bigint {
  return (amountDrops * BigInt(feeBps)) / 10_000n;
}

/**
 * Calculate net amount after fee deduction
 */
export function calculateNetAmount(amountDrops: bigint, feeBps: number = BRIDGE_FEE_BPS): bigint {
  const fee = calculateBridgeFee(amountDrops, feeBps);
  return amountDrops - fee;
}

/**
 * Convert Unix timestamp to XRPL Ripple epoch
 * @param unixTimestamp Unix epoch seconds
 * @returns Ripple epoch seconds
 */
export function unixToRippleEpoch(unixTimestamp: number): number {
  return unixTimestamp - RIPPLE_EPOCH_OFFSET;
}

/**
 * Convert XRPL Ripple epoch to Unix timestamp
 * @param rippleTimestamp Ripple epoch seconds
 * @returns Unix epoch seconds
 */
export function rippleEpochToUnix(rippleTimestamp: number): number {
  return rippleTimestamp + RIPPLE_EPOCH_OFFSET;
}

/**
 * Generate a random preimage for escrow conditions
 */
export function generatePreimage(): Hash {
  const randomBytes = new Uint8Array(32);
  crypto.getRandomValues(randomBytes);
  return toHex(randomBytes) as Hash;
}

/**
 * Compute SHA-256 condition from preimage (XRPL crypto-condition)
 * @param preimage The secret preimage
 * @returns SHA-256 hash of the preimage
 */
export function computeCondition(preimage: Hash): Hash {
  return sha256(toBytes(preimage));
}

/**
 * Validate escrow timelock parameters
 */
export function validateEscrowTimelocks(
  finishAfter: number,
  cancelAfter: number,
  currentTime: number = Math.floor(Date.now() / 1000)
): { valid: boolean; error?: string } {
  if (finishAfter < currentTime) {
    return { valid: false, error: 'finishAfter must be in the future' };
  }

  const duration = cancelAfter - finishAfter;

  if (duration < MIN_ESCROW_TIMELOCK) {
    return {
      valid: false,
      error: `Duration ${duration}s is below minimum ${MIN_ESCROW_TIMELOCK}s (1 hour)`,
    };
  }

  if (duration > MAX_ESCROW_TIMELOCK) {
    return {
      valid: false,
      error: `Duration ${duration}s exceeds maximum ${MAX_ESCROW_TIMELOCK}s (30 days)`,
    };
  }

  return { valid: true };
}

/**
 * Validate deposit amount is within bounds
 */
export function validateDepositAmount(amountDrops: bigint): { valid: boolean; error?: string } {
  if (amountDrops < MIN_DEPOSIT_DROPS) {
    return {
      valid: false,
      error: `Amount ${dropsToXrp(amountDrops)} XRP is below minimum ${dropsToXrp(MIN_DEPOSIT_DROPS)} XRP`,
    };
  }

  if (amountDrops > MAX_DEPOSIT_DROPS) {
    return {
      valid: false,
      error: `Amount ${dropsToXrp(amountDrops)} XRP exceeds maximum ${dropsToXrp(MAX_DEPOSIT_DROPS)} XRP`,
    };
  }

  return { valid: true };
}

/**
 * Estimate XRPL ledger confirmation time
 * @param confirmations Number of confirmations needed
 * @returns Estimated time in seconds (XRPL ledger closes ~3-5 seconds)
 */
export function estimateConfirmationTime(
  confirmations: number = REQUIRED_LEDGER_CONFIRMATIONS
): number {
  // XRPL average ledger close time is ~3.5 seconds
  return Math.ceil(confirmations * 3.5);
}

/**
 * Format drops as human-readable XRP string
 */
export function formatDrops(drops: bigint): string {
  const xrp = dropsToXrp(drops);
  return `${xrp.toLocaleString(undefined, { minimumFractionDigits: 0, maximumFractionDigits: 6 })} XRP`;
}

/*//////////////////////////////////////////////////////////////
                        ABI FRAGMENTS
//////////////////////////////////////////////////////////////*/

export const XRPL_BRIDGE_ADAPTER_ABI = [
  {
    name: 'configure',
    type: 'function',
    inputs: [
      { name: 'xrplMultisigAccount', type: 'bytes20' },
      { name: 'wrappedXRP', type: 'address' },
      { name: 'validatorOracle', type: 'address' },
      { name: 'minSignatures', type: 'uint256' },
      { name: 'requiredLedgerConfirmations', type: 'uint256' },
    ],
    outputs: [],
    stateMutability: 'nonpayable',
  },
  {
    name: 'initiateXRPDeposit',
    type: 'function',
    inputs: [
      { name: 'xrplTxHash', type: 'bytes32' },
      { name: 'xrplSender', type: 'bytes20' },
      { name: 'evmRecipient', type: 'address' },
      { name: 'amountDrops', type: 'uint256' },
      { name: 'destinationTag', type: 'bytes32' },
      { name: 'ledgerIndex', type: 'uint256' },
      {
        name: 'txProof',
        type: 'tuple',
        components: [
          { name: 'leafHash', type: 'bytes32' },
          { name: 'innerNodes', type: 'bytes32[]' },
          { name: 'nodeTypes', type: 'uint8[]' },
          { name: 'branchKeys', type: 'bytes32[]' },
        ],
      },
      {
        name: 'attestations',
        type: 'tuple[]',
        components: [
          { name: 'validatorPubKey', type: 'bytes32' },
          { name: 'signature', type: 'bytes' },
        ],
      },
    ],
    outputs: [{ name: 'depositId', type: 'bytes32' }],
    stateMutability: 'nonpayable',
  },
  {
    name: 'completeXRPDeposit',
    type: 'function',
    inputs: [{ name: 'depositId', type: 'bytes32' }],
    outputs: [],
    stateMutability: 'nonpayable',
  },
  {
    name: 'initiateWithdrawal',
    type: 'function',
    inputs: [
      { name: 'xrplRecipient', type: 'bytes20' },
      { name: 'amountDrops', type: 'uint256' },
    ],
    outputs: [{ name: 'withdrawalId', type: 'bytes32' }],
    stateMutability: 'nonpayable',
  },
  {
    name: 'completeWithdrawal',
    type: 'function',
    inputs: [
      { name: 'withdrawalId', type: 'bytes32' },
      { name: 'xrplTxHash', type: 'bytes32' },
      {
        name: 'txProof',
        type: 'tuple',
        components: [
          { name: 'leafHash', type: 'bytes32' },
          { name: 'innerNodes', type: 'bytes32[]' },
          { name: 'nodeTypes', type: 'uint8[]' },
          { name: 'branchKeys', type: 'bytes32[]' },
        ],
      },
      {
        name: 'attestations',
        type: 'tuple[]',
        components: [
          { name: 'validatorPubKey', type: 'bytes32' },
          { name: 'signature', type: 'bytes' },
        ],
      },
    ],
    outputs: [],
    stateMutability: 'nonpayable',
  },
  {
    name: 'refundWithdrawal',
    type: 'function',
    inputs: [{ name: 'withdrawalId', type: 'bytes32' }],
    outputs: [],
    stateMutability: 'nonpayable',
  },
  {
    name: 'createEscrow',
    type: 'function',
    inputs: [
      { name: 'xrplParty', type: 'bytes20' },
      { name: 'condition', type: 'bytes32' },
      { name: 'finishAfter', type: 'uint256' },
      { name: 'cancelAfter', type: 'uint256' },
    ],
    outputs: [{ name: 'escrowId', type: 'bytes32' }],
    stateMutability: 'payable',
  },
  {
    name: 'finishEscrow',
    type: 'function',
    inputs: [
      { name: 'escrowId', type: 'bytes32' },
      { name: 'fulfillment', type: 'bytes32' },
    ],
    outputs: [],
    stateMutability: 'nonpayable',
  },
  {
    name: 'cancelEscrow',
    type: 'function',
    inputs: [{ name: 'escrowId', type: 'bytes32' }],
    outputs: [],
    stateMutability: 'nonpayable',
  },
  {
    name: 'submitLedgerHeader',
    type: 'function',
    inputs: [
      { name: 'ledgerIndex', type: 'uint256' },
      { name: 'ledgerHash', type: 'bytes32' },
      { name: 'parentHash', type: 'bytes32' },
      { name: 'transactionHash', type: 'bytes32' },
      { name: 'accountStateHash', type: 'bytes32' },
      { name: 'closeTime', type: 'uint256' },
      {
        name: 'attestations',
        type: 'tuple[]',
        components: [
          { name: 'validatorPubKey', type: 'bytes32' },
          { name: 'signature', type: 'bytes' },
        ],
      },
    ],
    outputs: [],
    stateMutability: 'nonpayable',
  },
  {
    name: 'getDeposit',
    type: 'function',
    inputs: [{ name: 'depositId', type: 'bytes32' }],
    outputs: [
      {
        name: '',
        type: 'tuple',
        components: [
          { name: 'depositId', type: 'bytes32' },
          { name: 'xrplTxHash', type: 'bytes32' },
          { name: 'xrplSender', type: 'bytes20' },
          { name: 'evmRecipient', type: 'address' },
          { name: 'amountDrops', type: 'uint256' },
          { name: 'netAmountDrops', type: 'uint256' },
          { name: 'fee', type: 'uint256' },
          { name: 'destinationTag', type: 'bytes32' },
          { name: 'status', type: 'uint8' },
          { name: 'ledgerIndex', type: 'uint256' },
          { name: 'initiatedAt', type: 'uint256' },
          { name: 'completedAt', type: 'uint256' },
        ],
      },
    ],
    stateMutability: 'view',
  },
  {
    name: 'getWithdrawal',
    type: 'function',
    inputs: [{ name: 'withdrawalId', type: 'bytes32' }],
    outputs: [
      {
        name: '',
        type: 'tuple',
        components: [
          { name: 'withdrawalId', type: 'bytes32' },
          { name: 'evmSender', type: 'address' },
          { name: 'xrplRecipient', type: 'bytes20' },
          { name: 'amountDrops', type: 'uint256' },
          { name: 'xrplTxHash', type: 'bytes32' },
          { name: 'status', type: 'uint8' },
          { name: 'initiatedAt', type: 'uint256' },
          { name: 'completedAt', type: 'uint256' },
        ],
      },
    ],
    stateMutability: 'view',
  },
  {
    name: 'getEscrow',
    type: 'function',
    inputs: [{ name: 'escrowId', type: 'bytes32' }],
    outputs: [
      {
        name: '',
        type: 'tuple',
        components: [
          { name: 'escrowId', type: 'bytes32' },
          { name: 'evmParty', type: 'address' },
          { name: 'xrplParty', type: 'bytes20' },
          { name: 'amountDrops', type: 'uint256' },
          { name: 'condition', type: 'bytes32' },
          { name: 'fulfillment', type: 'bytes32' },
          { name: 'finishAfter', type: 'uint256' },
          { name: 'cancelAfter', type: 'uint256' },
          { name: 'xrplEscrowTxHash', type: 'bytes32' },
          { name: 'status', type: 'uint8' },
          { name: 'createdAt', type: 'uint256' },
        ],
      },
    ],
    stateMutability: 'view',
  },
  {
    name: 'getBridgeStats',
    type: 'function',
    inputs: [],
    outputs: [
      { name: 'totalDep', type: 'uint256' },
      { name: 'totalWith', type: 'uint256' },
      { name: 'totalEsc', type: 'uint256' },
      { name: 'totalEscFinished', type: 'uint256' },
      { name: 'totalEscCancelled', type: 'uint256' },
      { name: 'fees', type: 'uint256' },
      { name: 'latestLedger', type: 'uint256' },
    ],
    stateMutability: 'view',
  },
  {
    name: 'getLedgerHeader',
    type: 'function',
    inputs: [{ name: 'ledgerIndex', type: 'uint256' }],
    outputs: [
      {
        name: '',
        type: 'tuple',
        components: [
          { name: 'ledgerIndex', type: 'uint256' },
          { name: 'ledgerHash', type: 'bytes32' },
          { name: 'parentHash', type: 'bytes32' },
          { name: 'transactionHash', type: 'bytes32' },
          { name: 'accountStateHash', type: 'bytes32' },
          { name: 'closeTime', type: 'uint256' },
          { name: 'validated', type: 'bool' },
        ],
      },
    ],
    stateMutability: 'view',
  },
] as const;

export const WRAPPED_XRP_ABI = [
  {
    name: 'approve',
    type: 'function',
    inputs: [
      { name: 'spender', type: 'address' },
      { name: 'amount', type: 'uint256' },
    ],
    outputs: [{ name: '', type: 'bool' }],
    stateMutability: 'nonpayable',
  },
  {
    name: 'balanceOf',
    type: 'function',
    inputs: [{ name: 'account', type: 'address' }],
    outputs: [{ name: '', type: 'uint256' }],
    stateMutability: 'view',
  },
  {
    name: 'decimals',
    type: 'function',
    inputs: [],
    outputs: [{ name: '', type: 'uint8' }],
    stateMutability: 'view',
  },
  {
    name: 'totalSupply',
    type: 'function',
    inputs: [],
    outputs: [{ name: '', type: 'uint256' }],
    stateMutability: 'view',
  },
] as const;
