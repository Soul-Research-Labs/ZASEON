/**
 * @title ProtocolEmergencyCoordinator SDK Client
 * @description TypeScript client for multi-role emergency incident management.
 *
 * Three-phase workflow: Responders open/escalate incidents, Guardians execute
 * emergency plans, and Recovery operators validate and restore normal operations.
 */

import {
  PublicClient,
  WalletClient,
  getContract,
  Hex,
  decodeEventLog,
  Log,
} from "viem";
import { ViemContract, DecodedEventArgs } from "../types/contracts";

// ─── ABI ──────────────────────────────────────────────────────────────

const EMERGENCY_COORDINATOR_ABI = [
  // ── Write ──
  {
    name: "openIncident",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "severity", type: "uint8" },
      { name: "reason", type: "string" },
      { name: "evidenceHash", type: "bytes32" },
    ],
    outputs: [{ name: "incidentId", type: "uint256" }],
  },
  {
    name: "escalateIncident",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "incidentId", type: "uint256" },
      { name: "newSeverity", type: "uint8" },
    ],
    outputs: [],
  },
  {
    name: "executeEmergencyPlan",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "incidentId", type: "uint256" }],
    outputs: [],
  },
  {
    name: "executeRecovery",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "incidentId", type: "uint256" }],
    outputs: [],
  },
  {
    name: "confirmRoleSeparation",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [],
    outputs: [],
  },
  // ── Read ──
  {
    name: "currentSeverity",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "uint8" }],
  },
  {
    name: "activeIncidentId",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "uint256" }],
  },
  {
    name: "incidentCount",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "uint256" }],
  },
  {
    name: "lastEscalationAt",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "uint48" }],
  },
  {
    name: "roleSeparationConfirmed",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "bool" }],
  },
  {
    name: "hasActiveIncident",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "bool" }],
  },
  {
    name: "getIncident",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "incidentId", type: "uint256" }],
    outputs: [
      {
        name: "",
        type: "tuple",
        components: [
          { name: "id", type: "uint256" },
          { name: "severity", type: "uint8" },
          { name: "initiator", type: "address" },
          { name: "timestamp", type: "uint48" },
          { name: "resolvedAt", type: "uint48" },
          { name: "reason", type: "string" },
          { name: "evidenceHash", type: "bytes32" },
        ],
      },
    ],
  },
  {
    name: "getIncidents",
    type: "function",
    stateMutability: "view",
    inputs: [
      { name: "from", type: "uint256" },
      { name: "to", type: "uint256" },
    ],
    outputs: [
      {
        name: "",
        type: "tuple[]",
        components: [
          { name: "id", type: "uint256" },
          { name: "severity", type: "uint8" },
          { name: "initiator", type: "address" },
          { name: "timestamp", type: "uint48" },
          { name: "resolvedAt", type: "uint48" },
          { name: "reason", type: "string" },
          { name: "evidenceHash", type: "bytes32" },
        ],
      },
    ],
  },
  {
    name: "getSubsystemStatus",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [
      {
        name: "",
        type: "tuple",
        components: [
          { name: "healthAggregatorHealthy", type: "bool" },
          { name: "emergencyRecoveryMonitoring", type: "bool" },
          { name: "killSwitchNone", type: "bool" },
          { name: "circuitBreakerNormal", type: "bool" },
          { name: "hubPaused", type: "bool" },
        ],
      },
    ],
  },
  {
    name: "validateRecovery",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "incidentId", type: "uint256" }],
    outputs: [
      { name: "allClear", type: "bool" },
      {
        name: "status",
        type: "tuple",
        components: [
          { name: "healthAggregatorHealthy", type: "bool" },
          { name: "emergencyRecoveryMonitoring", type: "bool" },
          { name: "killSwitchNone", type: "bool" },
          { name: "circuitBreakerNormal", type: "bool" },
          { name: "hubPaused", type: "bool" },
        ],
      },
    ],
  },
  {
    name: "planExecuted",
    type: "function",
    stateMutability: "view",
    inputs: [
      { name: "incidentId", type: "uint256" },
      { name: "sev", type: "uint8" },
    ],
    outputs: [{ name: "", type: "bool" }],
  },
  // ── Events ──
  {
    name: "IncidentOpened",
    type: "event",
    inputs: [
      { name: "incidentId", type: "uint256", indexed: true },
      { name: "severity", type: "uint8", indexed: false },
      { name: "initiator", type: "address", indexed: true },
      { name: "reason", type: "string", indexed: false },
    ],
  },
  {
    name: "IncidentResolved",
    type: "event",
    inputs: [
      { name: "incidentId", type: "uint256", indexed: true },
      { name: "severity", type: "uint8", indexed: false },
      { name: "resolver", type: "address", indexed: true },
    ],
  },
  {
    name: "SeverityEscalated",
    type: "event",
    inputs: [
      { name: "oldLevel", type: "uint8", indexed: true },
      { name: "newLevel", type: "uint8", indexed: true },
      { name: "incidentId", type: "uint256", indexed: true },
    ],
  },
  {
    name: "EmergencyPlanExecuted",
    type: "event",
    inputs: [
      { name: "severity", type: "uint8", indexed: false },
      { name: "incidentId", type: "uint256", indexed: true },
      { name: "actionsPerformed", type: "uint8", indexed: false },
    ],
  },
  {
    name: "RecoveryExecuted",
    type: "event",
    inputs: [
      { name: "incidentId", type: "uint256", indexed: true },
      { name: "newSeverity", type: "uint8", indexed: false },
    ],
  },
  {
    name: "RoleSeparationConfirmed",
    type: "event",
    inputs: [
      { name: "confirmedBy", type: "address", indexed: true },
    ],
  },
] as const;

// ─── Types ────────────────────────────────────────────────────────────

/** Severity level matching on-chain Severity enum */
export enum Severity {
  GREEN = 0,
  YELLOW = 1,
  ORANGE = 2,
  RED = 3,
  BLACK = 4,
}

/** On-chain incident record */
export interface Incident {
  id: bigint;
  severity: Severity;
  initiator: Hex;
  timestamp: bigint;
  resolvedAt: bigint;
  reason: string;
  evidenceHash: Hex;
}

/** Subsystem health status */
export interface SubsystemStatus {
  healthAggregatorHealthy: boolean;
  emergencyRecoveryMonitoring: boolean;
  killSwitchNone: boolean;
  circuitBreakerNormal: boolean;
  hubPaused: boolean;
}

/** Recovery validation result */
export interface RecoveryValidation {
  allClear: boolean;
  status: SubsystemStatus;
}

/** Result from opening an incident */
export interface OpenIncidentResult {
  txHash: Hex;
  incidentId: bigint;
}

// ─── Client ───────────────────────────────────────────────────────────

/**
 * SDK client for the ProtocolEmergencyCoordinator contract.
 *
 * Provides typed access to the three-phase incident management workflow:
 * 1. **Responders** open and escalate incidents
 * 2. **Guardians** execute emergency plans
 * 3. **Recovery operators** validate and restore normal operations
 *
 * @example
 * ```ts
 * const coord = new ProtocolEmergencyCoordinatorClient(address, publicClient, walletClient);
 *
 * // Open an incident
 * const { incidentId } = await coord.openIncident(Severity.RED, "Bridge exploit", evidenceHash);
 *
 * // Execute emergency plan
 * await coord.executeEmergencyPlan(incidentId);
 *
 * // After remediation, validate and recover
 * const { allClear } = await coord.validateRecovery(incidentId);
 * if (allClear) await coord.executeRecovery(incidentId);
 * ```
 */
export class ProtocolEmergencyCoordinatorClient {
  public readonly contract: ViemContract;
  private readonly publicClient: PublicClient;
  private readonly walletClient?: WalletClient;

  constructor(
    contractAddress: Hex,
    publicClient: PublicClient,
    walletClient?: WalletClient,
  ) {
    this.publicClient = publicClient;
    this.walletClient = walletClient;
    this.contract = getContract({
      address: contractAddress,
      abi: EMERGENCY_COORDINATOR_ABI,
      client: { public: publicClient, wallet: walletClient },
    }) as unknown as ViemContract;
  }

  // ── Write: Incident Management ────────────────────────────────────

  /**
   * Open a new incident. Requires RESPONDER_ROLE.
   *
   * @param severity - Incident severity (YELLOW through BLACK)
   * @param reason - Human-readable description
   * @param evidenceHash - Hash of off-chain evidence data
   * @returns Transaction hash and incident ID
   */
  async openIncident(
    severity: Severity,
    reason: string,
    evidenceHash: Hex,
  ): Promise<OpenIncidentResult> {
    if (!this.walletClient) throw new Error("Wallet client required for write operations");
    const hash = await this.contract.write.openIncident([
      severity,
      reason,
      evidenceHash,
    ]);
    const receipt = await this.publicClient.waitForTransactionReceipt({ hash });

    let incidentId = 0n;
    for (const log of receipt.logs) {
      try {
        const decoded = decodeEventLog({
          abi: EMERGENCY_COORDINATOR_ABI,
          data: log.data,
          topics: log.topics,
        });
        if (decoded.eventName === "IncidentOpened") {
          const args = decoded.args as DecodedEventArgs;
          incidentId = args["incidentId"] as bigint;
          break;
        }
      } catch {
        // Not our event
      }
    }

    return { txHash: hash, incidentId };
  }

  /**
   * Escalate an active incident to a higher severity. Requires RESPONDER_ROLE.
   *
   * Subject to a 5-minute cooldown between escalations.
   *
   * @param incidentId - ID of the active incident
   * @param newSeverity - Target severity (must be higher than current)
   * @returns Transaction hash
   */
  async escalateIncident(
    incidentId: bigint,
    newSeverity: Severity,
  ): Promise<Hex> {
    if (!this.walletClient) throw new Error("Wallet client required for write operations");
    const hash = await this.contract.write.escalateIncident([
      incidentId,
      newSeverity,
    ]);
    await this.publicClient.waitForTransactionReceipt({ hash });
    return hash;
  }

  /**
   * Execute emergency plan for the current severity. Requires GUARDIAN_ROLE.
   *
   * For RED/BLACK severity, `confirmRoleSeparation()` must have been called first.
   * Cascades actions to subsystems (kill switch, circuit breaker, hub pause, etc.).
   *
   * @param incidentId - ID of the active incident
   * @returns Transaction hash
   */
  async executeEmergencyPlan(incidentId: bigint): Promise<Hex> {
    if (!this.walletClient) throw new Error("Wallet client required for write operations");
    const hash = await this.contract.write.executeEmergencyPlan([incidentId]);
    await this.publicClient.waitForTransactionReceipt({ hash });
    return hash;
  }

  /**
   * Execute recovery and resolve the incident. Requires RECOVERY_ROLE.
   *
   * Subject to 1-hour cooldown after last escalation. All subsystems must
   * report healthy (validated via `validateRecovery` first).
   *
   * @param incidentId - ID of the incident to resolve
   * @returns Transaction hash
   */
  async executeRecovery(incidentId: bigint): Promise<Hex> {
    if (!this.walletClient) throw new Error("Wallet client required for write operations");
    const hash = await this.contract.write.executeRecovery([incidentId]);
    await this.publicClient.waitForTransactionReceipt({ hash });
    return hash;
  }

  /**
   * Confirm role separation. Requires DEFAULT_ADMIN_ROLE.
   *
   * Validates that no single address holds multiple operational roles
   * (GUARDIAN + RESPONDER, GUARDIAN + RECOVERY, or RESPONDER + RECOVERY).
   * Must be called before RED/BLACK emergency plans can execute.
   *
   * @returns Transaction hash
   */
  async confirmRoleSeparation(): Promise<Hex> {
    if (!this.walletClient) throw new Error("Wallet client required for write operations");
    const hash = await this.contract.write.confirmRoleSeparation([]);
    await this.publicClient.waitForTransactionReceipt({ hash });
    return hash;
  }

  // ── Read Methods ──────────────────────────────────────────────────

  /** Get the current protocol severity level. */
  async getCurrentSeverity(): Promise<Severity> {
    const raw = await this.contract.read.currentSeverity([]);
    return Number(raw) as Severity;
  }

  /** Get the active incident ID (0 if none). */
  async getActiveIncidentId(): Promise<bigint> {
    return (await this.contract.read.activeIncidentId([])) as bigint;
  }

  /** Get total number of incidents ever created. */
  async getIncidentCount(): Promise<bigint> {
    return (await this.contract.read.incidentCount([])) as bigint;
  }

  /** Get timestamp of last escalation. */
  async getLastEscalationAt(): Promise<bigint> {
    return BigInt((await this.contract.read.lastEscalationAt([])) as number);
  }

  /** Check if role separation has been confirmed. */
  async isRoleSeparationConfirmed(): Promise<boolean> {
    return (await this.contract.read.roleSeparationConfirmed([])) as boolean;
  }

  /** Check if there is an active incident. */
  async hasActiveIncident(): Promise<boolean> {
    return (await this.contract.read.hasActiveIncident([])) as boolean;
  }

  /** Get a specific incident by ID. */
  async getIncident(incidentId: bigint): Promise<Incident> {
    const raw = await this.contract.read.getIncident([incidentId]);
    const r = raw as Record<string, unknown>;
    return {
      id: BigInt(r.id as bigint),
      severity: Number(r.severity) as Severity,
      initiator: r.initiator as Hex,
      timestamp: BigInt(r.timestamp as number),
      resolvedAt: BigInt(r.resolvedAt as number),
      reason: r.reason as string,
      evidenceHash: r.evidenceHash as Hex,
    };
  }

  /** Get a range of incidents (paginated). */
  async getIncidents(from: bigint, to: bigint): Promise<Incident[]> {
    const raw = await this.contract.read.getIncidents([from, to]);
    const arr = raw as Array<Record<string, unknown>>;
    return arr.map((r) => ({
      id: BigInt(r.id as bigint),
      severity: Number(r.severity) as Severity,
      initiator: r.initiator as Hex,
      timestamp: BigInt(r.timestamp as number),
      resolvedAt: BigInt(r.resolvedAt as number),
      reason: r.reason as string,
      evidenceHash: r.evidenceHash as Hex,
    }));
  }

  /** Get current health status of all subsystems. */
  async getSubsystemStatus(): Promise<SubsystemStatus> {
    const raw = await this.contract.read.getSubsystemStatus([]);
    const r = raw as Record<string, boolean>;
    return {
      healthAggregatorHealthy: r.healthAggregatorHealthy,
      emergencyRecoveryMonitoring: r.emergencyRecoveryMonitoring,
      killSwitchNone: r.killSwitchNone,
      circuitBreakerNormal: r.circuitBreakerNormal,
      hubPaused: r.hubPaused,
    };
  }

  /**
   * Validate whether recovery can proceed for an incident.
   *
   * All subsystems must report healthy for recovery to succeed.
   */
  async validateRecovery(incidentId: bigint): Promise<RecoveryValidation> {
    const [allClear, statusRaw] = (await this.contract.read.validateRecovery([
      incidentId,
    ])) as [boolean, Record<string, boolean>];
    return {
      allClear,
      status: {
        healthAggregatorHealthy: statusRaw.healthAggregatorHealthy,
        emergencyRecoveryMonitoring: statusRaw.emergencyRecoveryMonitoring,
        killSwitchNone: statusRaw.killSwitchNone,
        circuitBreakerNormal: statusRaw.circuitBreakerNormal,
        hubPaused: statusRaw.hubPaused,
      },
    };
  }

  /** Check if emergency plan was executed for a specific incident and severity. */
  async isPlanExecuted(
    incidentId: bigint,
    severity: Severity,
  ): Promise<boolean> {
    return (await this.contract.read.planExecuted([
      incidentId,
      severity,
    ])) as boolean;
  }

  // ── Event Watchers ────────────────────────────────────────────────

  /**
   * Watch for new incidents being opened.
   * @returns An unwatch function to stop listening
   */
  watchIncidentOpened(
    callback: (
      incidentId: bigint,
      severity: Severity,
      initiator: Hex,
      reason: string,
    ) => void,
  ) {
    return this.publicClient.watchContractEvent({
      address: this.contract.address as Hex,
      abi: EMERGENCY_COORDINATOR_ABI,
      eventName: "IncidentOpened",
      onLogs: (logs: Log[]) => {
        for (const log of logs) {
          try {
            const decoded = decodeEventLog({
              abi: EMERGENCY_COORDINATOR_ABI,
              data: log.data,
              topics: log.topics,
            });
            if (decoded.eventName === "IncidentOpened") {
              const args = decoded.args as DecodedEventArgs;
              callback(
                args["incidentId"] as bigint,
                Number(args["severity"]) as Severity,
                args["initiator"] as Hex,
                args["reason"] as string,
              );
            }
          } catch {
            // Skip
          }
        }
      },
    });
  }

  /**
   * Watch for severity escalations.
   * @returns An unwatch function to stop listening
   */
  watchSeverityEscalated(
    callback: (
      oldLevel: Severity,
      newLevel: Severity,
      incidentId: bigint,
    ) => void,
  ) {
    return this.publicClient.watchContractEvent({
      address: this.contract.address as Hex,
      abi: EMERGENCY_COORDINATOR_ABI,
      eventName: "SeverityEscalated",
      onLogs: (logs: Log[]) => {
        for (const log of logs) {
          try {
            const decoded = decodeEventLog({
              abi: EMERGENCY_COORDINATOR_ABI,
              data: log.data,
              topics: log.topics,
            });
            if (decoded.eventName === "SeverityEscalated") {
              const args = decoded.args as DecodedEventArgs;
              callback(
                Number(args["oldLevel"]) as Severity,
                Number(args["newLevel"]) as Severity,
                args["incidentId"] as bigint,
              );
            }
          } catch {
            // Skip
          }
        }
      },
    });
  }

  /**
   * Watch for emergency plan executions.
   * @returns An unwatch function to stop listening
   */
  watchEmergencyPlanExecuted(
    callback: (incidentId: bigint, severity: Severity) => void,
  ) {
    return this.publicClient.watchContractEvent({
      address: this.contract.address as Hex,
      abi: EMERGENCY_COORDINATOR_ABI,
      eventName: "EmergencyPlanExecuted",
      onLogs: (logs: Log[]) => {
        for (const log of logs) {
          try {
            const decoded = decodeEventLog({
              abi: EMERGENCY_COORDINATOR_ABI,
              data: log.data,
              topics: log.topics,
            });
            if (decoded.eventName === "EmergencyPlanExecuted") {
              const args = decoded.args as DecodedEventArgs;
              callback(
                args["incidentId"] as bigint,
                Number(args["severity"]) as Severity,
              );
            }
          } catch {
            // Skip
          }
        }
      },
    });
  }

  /**
   * Watch for incident resolution events.
   * @returns An unwatch function to stop listening
   */
  watchIncidentResolved(
    callback: (incidentId: bigint, resolver: Hex) => void,
  ) {
    return this.publicClient.watchContractEvent({
      address: this.contract.address as Hex,
      abi: EMERGENCY_COORDINATOR_ABI,
      eventName: "IncidentResolved",
      onLogs: (logs: Log[]) => {
        for (const log of logs) {
          try {
            const decoded = decodeEventLog({
              abi: EMERGENCY_COORDINATOR_ABI,
              data: log.data,
              topics: log.topics,
            });
            if (decoded.eventName === "IncidentResolved") {
              const args = decoded.args as DecodedEventArgs;
              callback(
                args["incidentId"] as bigint,
                args["resolver"] as Hex,
              );
            }
          } catch {
            // Skip
          }
        }
      },
    });
  }

}
