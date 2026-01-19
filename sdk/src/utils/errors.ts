/**
 * PIL SDK Error Classes
 * 
 * Comprehensive error handling with typed errors, error codes,
 * and contextual information for debugging.
 */

/**
 * Base error code enum for all PIL SDK errors
 */
export enum PILErrorCode {
  // General errors (1xxx)
  UNKNOWN_ERROR = 1000,
  INVALID_CONFIGURATION = 1001,
  NETWORK_ERROR = 1002,
  TIMEOUT_ERROR = 1003,
  RATE_LIMITED = 1004,

  // Validation errors (2xxx)
  INVALID_INPUT = 2000,
  INVALID_ADDRESS = 2001,
  INVALID_PROOF = 2002,
  INVALID_NULLIFIER = 2003,
  INVALID_POLICY = 2004,
  INVALID_COMMITMENT = 2005,
  INVALID_SIGNATURE = 2006,
  SCHEMA_VALIDATION_FAILED = 2007,

  // Contract errors (3xxx)
  CONTRACT_CALL_FAILED = 3000,
  TRANSACTION_REVERTED = 3001,
  INSUFFICIENT_GAS = 3002,
  NONCE_TOO_LOW = 3003,
  REPLACEMENT_UNDERPRICED = 3004,
  CONTRACT_NOT_DEPLOYED = 3005,
  UNSUPPORTED_CHAIN = 3006,

  // State errors (4xxx)
  NULLIFIER_ALREADY_CONSUMED = 4000,
  CONTAINER_NOT_FOUND = 4001,
  CONTAINER_ALREADY_CONSUMED = 4002,
  POLICY_NOT_FOUND = 4003,
  POLICY_EXPIRED = 4004,
  POLICY_INACTIVE = 4005,
  COMMITMENT_NOT_FOUND = 4006,
  BACKEND_INACTIVE = 4007,
  DOMAIN_INACTIVE = 4008,

  // Proof errors (5xxx)
  PROOF_GENERATION_FAILED = 5000,
  PROOF_VERIFICATION_FAILED = 5001,
  PROOF_EXPIRED = 5002,
  PROOF_OUT_OF_SCOPE = 5003,
  WITNESS_GENERATION_FAILED = 5004,
  CIRCUIT_NOT_FOUND = 5005,

  // TEE errors (6xxx)
  TEE_ATTESTATION_FAILED = 6000,
  TEE_ENCLAVE_NOT_TRUSTED = 6001,
  TEE_QUOTE_EXPIRED = 6002,
  TEE_PLATFORM_UNSUPPORTED = 6003,

  // Compliance errors (7xxx)
  COMPLIANCE_CHECK_FAILED = 7000,
  JURISDICTION_BLOCKED = 7001,
  AMOUNT_EXCEEDS_LIMIT = 7002,
  COUNTERPARTY_BLOCKED = 7003,
  ASSET_NOT_ALLOWED = 7004,
}

/**
 * Error metadata interface
 */
export interface PILErrorMetadata {
  code: PILErrorCode;
  timestamp: Date;
  context?: Record<string, unknown>;
  cause?: Error;
  retryable: boolean;
  suggestedAction?: string;
}

/**
 * Base PIL SDK Error
 */
export class PILError extends Error {
  public readonly code: PILErrorCode;
  public readonly timestamp: Date;
  public readonly context: Record<string, unknown>;
  public readonly cause?: Error;
  public readonly retryable: boolean;
  public readonly suggestedAction?: string;

  constructor(
    message: string,
    code: PILErrorCode = PILErrorCode.UNKNOWN_ERROR,
    options: Partial<PILErrorMetadata> = {}
  ) {
    super(message);
    this.name = "PILError";
    this.code = code;
    this.timestamp = options.timestamp || new Date();
    this.context = options.context || {};
    this.cause = options.cause;
    this.retryable = options.retryable ?? false;
    this.suggestedAction = options.suggestedAction;

    // Maintains proper stack trace for where error was thrown
    Error.captureStackTrace?.(this, this.constructor);
  }

  /**
   * Create a JSON representation of the error
   */
  toJSON(): Record<string, unknown> {
    return {
      name: this.name,
      message: this.message,
      code: this.code,
      codeName: PILErrorCode[this.code],
      timestamp: this.timestamp.toISOString(),
      context: this.context,
      retryable: this.retryable,
      suggestedAction: this.suggestedAction,
      stack: this.stack,
      cause: this.cause?.message,
    };
  }

  /**
   * Check if error is of a specific type
   */
  isType(code: PILErrorCode): boolean {
    return this.code === code;
  }

  /**
   * Check if error is in a category (by code range)
   */
  isCategory(category: "general" | "validation" | "contract" | "state" | "proof" | "tee" | "compliance"): boolean {
    const ranges: Record<string, [number, number]> = {
      general: [1000, 1999],
      validation: [2000, 2999],
      contract: [3000, 3999],
      state: [4000, 4999],
      proof: [5000, 5999],
      tee: [6000, 6999],
      compliance: [7000, 7999],
    };
    const [min, max] = ranges[category];
    return this.code >= min && this.code <= max;
  }
}

/**
 * Validation Error
 */
export class ValidationError extends PILError {
  constructor(
    message: string,
    code: PILErrorCode = PILErrorCode.INVALID_INPUT,
    context?: Record<string, unknown>
  ) {
    super(message, code, {
      context,
      retryable: false,
      suggestedAction: "Check input parameters and try again",
    });
    this.name = "ValidationError";
  }
}

/**
 * Contract Error
 */
export class ContractError extends PILError {
  public readonly transactionHash?: string;
  public readonly revertReason?: string;

  constructor(
    message: string,
    code: PILErrorCode = PILErrorCode.CONTRACT_CALL_FAILED,
    options: {
      transactionHash?: string;
      revertReason?: string;
      context?: Record<string, unknown>;
      cause?: Error;
    } = {}
  ) {
    super(message, code, {
      context: {
        ...options.context,
        transactionHash: options.transactionHash,
        revertReason: options.revertReason,
      },
      cause: options.cause,
      retryable: [
        PILErrorCode.NONCE_TOO_LOW,
        PILErrorCode.REPLACEMENT_UNDERPRICED,
        PILErrorCode.NETWORK_ERROR,
      ].includes(code),
      suggestedAction: options.revertReason
        ? `Transaction reverted: ${options.revertReason}`
        : "Check transaction parameters and gas settings",
    });
    this.name = "ContractError";
    this.transactionHash = options.transactionHash;
    this.revertReason = options.revertReason;
  }
}

/**
 * Network Error
 */
export class NetworkError extends PILError {
  public readonly endpoint?: string;
  public readonly statusCode?: number;

  constructor(
    message: string,
    options: {
      endpoint?: string;
      statusCode?: number;
      cause?: Error;
    } = {}
  ) {
    super(message, PILErrorCode.NETWORK_ERROR, {
      context: {
        endpoint: options.endpoint,
        statusCode: options.statusCode,
      },
      cause: options.cause,
      retryable: true,
      suggestedAction: "Check network connectivity and try again",
    });
    this.name = "NetworkError";
    this.endpoint = options.endpoint;
    this.statusCode = options.statusCode;
  }
}

/**
 * Proof Error
 */
export class ProofError extends PILError {
  public readonly proofType?: string;
  public readonly circuitId?: string;

  constructor(
    message: string,
    code: PILErrorCode = PILErrorCode.PROOF_GENERATION_FAILED,
    options: {
      proofType?: string;
      circuitId?: string;
      context?: Record<string, unknown>;
      cause?: Error;
    } = {}
  ) {
    super(message, code, {
      context: {
        ...options.context,
        proofType: options.proofType,
        circuitId: options.circuitId,
      },
      cause: options.cause,
      retryable: code === PILErrorCode.PROOF_EXPIRED,
      suggestedAction:
        code === PILErrorCode.PROOF_EXPIRED
          ? "Generate a new proof with updated timestamp"
          : "Check proof inputs and circuit compatibility",
    });
    this.name = "ProofError";
    this.proofType = options.proofType;
    this.circuitId = options.circuitId;
  }
}

/**
 * State Error
 */
export class StateError extends PILError {
  public readonly entityId?: string;
  public readonly entityType?: string;

  constructor(
    message: string,
    code: PILErrorCode = PILErrorCode.CONTAINER_NOT_FOUND,
    options: {
      entityId?: string;
      entityType?: string;
      context?: Record<string, unknown>;
    } = {}
  ) {
    super(message, code, {
      context: {
        ...options.context,
        entityId: options.entityId,
        entityType: options.entityType,
      },
      retryable: false,
      suggestedAction: "Verify entity exists and is in correct state",
    });
    this.name = "StateError";
    this.entityId = options.entityId;
    this.entityType = options.entityType;
  }
}

/**
 * Compliance Error
 */
export class ComplianceError extends PILError {
  public readonly policyId?: string;
  public readonly violation?: string;

  constructor(
    message: string,
    code: PILErrorCode = PILErrorCode.COMPLIANCE_CHECK_FAILED,
    options: {
      policyId?: string;
      violation?: string;
      context?: Record<string, unknown>;
    } = {}
  ) {
    super(message, code, {
      context: {
        ...options.context,
        policyId: options.policyId,
        violation: options.violation,
      },
      retryable: false,
      suggestedAction: "Review compliance policy requirements",
    });
    this.name = "ComplianceError";
    this.policyId = options.policyId;
    this.violation = options.violation;
  }
}

/**
 * Timeout Error
 */
export class TimeoutError extends PILError {
  public readonly timeoutMs: number;
  public readonly operation: string;

  constructor(operation: string, timeoutMs: number) {
    super(
      `Operation "${operation}" timed out after ${timeoutMs}ms`,
      PILErrorCode.TIMEOUT_ERROR,
      {
        context: { operation, timeoutMs },
        retryable: true,
        suggestedAction: "Increase timeout or check network latency",
      }
    );
    this.name = "TimeoutError";
    this.timeoutMs = timeoutMs;
    this.operation = operation;
  }
}

/**
 * Error factory for creating errors from contract reverts
 */
export function parseContractError(error: Error): ContractError {
  const message = error.message || "Contract call failed";
  
  // Parse common revert reasons
  if (message.includes("NullifierAlreadyConsumed")) {
    return new ContractError(
      "Nullifier has already been consumed",
      PILErrorCode.NULLIFIER_ALREADY_CONSUMED,
      { cause: error, revertReason: "NullifierAlreadyConsumed" }
    );
  }
  
  if (message.includes("ContainerNotFound")) {
    return new ContractError(
      "Container not found",
      PILErrorCode.CONTAINER_NOT_FOUND,
      { cause: error, revertReason: "ContainerNotFound" }
    );
  }
  
  if (message.includes("PolicyNotFound")) {
    return new ContractError(
      "Policy not found",
      PILErrorCode.POLICY_NOT_FOUND,
      { cause: error, revertReason: "PolicyNotFound" }
    );
  }
  
  if (message.includes("PolicyExpired")) {
    return new ContractError(
      "Policy has expired",
      PILErrorCode.POLICY_EXPIRED,
      { cause: error, revertReason: "PolicyExpired" }
    );
  }
  
  if (message.includes("nonce too low")) {
    return new ContractError(
      "Transaction nonce too low",
      PILErrorCode.NONCE_TOO_LOW,
      { cause: error }
    );
  }
  
  if (message.includes("replacement transaction underpriced")) {
    return new ContractError(
      "Replacement transaction underpriced",
      PILErrorCode.REPLACEMENT_UNDERPRICED,
      { cause: error }
    );
  }

  // Default contract error
  return new ContractError(message, PILErrorCode.CONTRACT_CALL_FAILED, {
    cause: error,
  });
}

/**
 * Type guard for PIL errors
 */
export function isPILError(error: unknown): error is PILError {
  return error instanceof PILError;
}
