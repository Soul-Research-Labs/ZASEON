import {
  Finding,
  HandleTransaction,
  TransactionEvent,
  FindingSeverity,
  FindingType,
  ethers,
} from "forta-agent";

// PIL v2 Contract Addresses (update after deployment)
const CONTRACTS = {
  PC3: process.env.PC3_ADDRESS || "",
  PBP: process.env.PBP_ADDRESS || "",
  EASC: process.env.EASC_ADDRESS || "",
  CDNA: process.env.CDNA_ADDRESS || "",
  ORCHESTRATOR: process.env.ORCHESTRATOR_ADDRESS || "",
  TIMELOCK: process.env.TIMELOCK_ADDRESS || "",
};

// Event signatures for monitoring
const EVENTS = {
  // Critical Events - Require immediate attention
  CONTAINER_CONSUMED: "ContainerConsumed(bytes32,address,uint256)",
  NULLIFIER_CONSUMED: "NullifierConsumed(bytes32,bytes32,uint256)",
  POLICY_DEACTIVATED: "PolicyDeactivated(bytes32)",
  BACKEND_DEACTIVATED: "BackendDeactivated(bytes32)",
  PAUSED: "Paused(address)",
  UNPAUSED: "Unpaused(address)",
  
  // Governance Events
  TIMELOCK_SCHEDULED: "CallScheduled(bytes32,uint256,address,uint256,bytes,bytes32,uint256)",
  TIMELOCK_EXECUTED: "CallExecuted(bytes32,uint256,address,uint256,bytes)",
  TIMELOCK_CANCELLED: "Cancelled(bytes32)",
  
  // High-Value Events
  CONTAINER_CREATED: "ContainerCreated(bytes32,address,bytes32,bytes32,uint256)",
  COMMITMENT_FINALIZED: "CommitmentFinalized(bytes32,uint256,uint256)",
  
  // Suspicious Activity
  ROLE_GRANTED: "RoleGranted(bytes32,address,address)",
  ROLE_REVOKED: "RoleRevoked(bytes32,address,address)",
};

// Thresholds for alerts
const THRESHOLDS = {
  HIGH_GAS_LIMIT: 10_000_000,
  RAPID_CONTAINER_CREATION: 10, // Per block
  SUSPICIOUS_NULLIFIER_PATTERN: 5, // Rapid consumptions
};

// Track activity for pattern detection
const activityTracker: Map<string, number[]> = new Map();

/**
 * Main transaction handler
 */
const handleTransaction: HandleTransaction = async (
  txEvent: TransactionEvent
) => {
  const findings: Finding[] = [];

  // Check for contract interactions
  const allAddresses = Object.values(CONTRACTS).filter(Boolean);
  if (!allAddresses.some(addr => txEvent.addresses[addr.toLowerCase()])) {
    return findings;
  }

  // 1. Monitor for pause/unpause events
  findings.push(...detectPauseEvents(txEvent));

  // 2. Monitor for governance actions
  findings.push(...detectGovernanceActions(txEvent));

  // 3. Monitor for high-volume activity
  findings.push(...detectHighVolumeActivity(txEvent));

  // 4. Monitor for role changes
  findings.push(...detectRoleChanges(txEvent));

  // 5. Monitor for nullifier double-spend attempts
  findings.push(...detectDoubleSpendAttempts(txEvent));

  // 6. Monitor for suspicious gas usage
  findings.push(...detectSuspiciousGas(txEvent));

  return findings;
};

/**
 * Detect pause/unpause events
 */
function detectPauseEvents(txEvent: TransactionEvent): Finding[] {
  const findings: Finding[] = [];
  
  const pauseEvents = txEvent.filterLog(EVENTS.PAUSED);
  const unpauseEvents = txEvent.filterLog(EVENTS.UNPAUSED);

  for (const event of pauseEvents) {
    findings.push(
      Finding.fromObject({
        name: "PIL Contract Paused",
        description: `A PIL v2 contract was paused by ${event.args[0]}`,
        alertId: "PIL-PAUSED",
        severity: FindingSeverity.Critical,
        type: FindingType.Suspicious,
        metadata: {
          pauser: event.args[0],
          contract: event.address,
          txHash: txEvent.hash,
        },
      })
    );
  }

  for (const event of unpauseEvents) {
    findings.push(
      Finding.fromObject({
        name: "PIL Contract Unpaused",
        description: `A PIL v2 contract was unpaused by ${event.args[0]}`,
        alertId: "PIL-UNPAUSED",
        severity: FindingSeverity.High,
        type: FindingType.Info,
        metadata: {
          unpauser: event.args[0],
          contract: event.address,
          txHash: txEvent.hash,
        },
      })
    );
  }

  return findings;
}

/**
 * Detect governance/timelock actions
 */
function detectGovernanceActions(txEvent: TransactionEvent): Finding[] {
  const findings: Finding[] = [];

  // Scheduled operations
  const scheduledEvents = txEvent.filterLog(EVENTS.TIMELOCK_SCHEDULED);
  for (const event of scheduledEvents) {
    findings.push(
      Finding.fromObject({
        name: "Timelock Operation Scheduled",
        description: "A new timelock operation has been scheduled",
        alertId: "PIL-TIMELOCK-SCHEDULED",
        severity: FindingSeverity.Medium,
        type: FindingType.Info,
        metadata: {
          operationId: event.args[0],
          target: event.args[2],
          delay: event.args[6]?.toString(),
          txHash: txEvent.hash,
        },
      })
    );
  }

  // Executed operations
  const executedEvents = txEvent.filterLog(EVENTS.TIMELOCK_EXECUTED);
  for (const event of executedEvents) {
    findings.push(
      Finding.fromObject({
        name: "Timelock Operation Executed",
        description: "A timelock operation has been executed",
        alertId: "PIL-TIMELOCK-EXECUTED",
        severity: FindingSeverity.High,
        type: FindingType.Info,
        metadata: {
          operationId: event.args[0],
          target: event.args[2],
          txHash: txEvent.hash,
        },
      })
    );
  }

  // Cancelled operations
  const cancelledEvents = txEvent.filterLog(EVENTS.TIMELOCK_CANCELLED);
  for (const event of cancelledEvents) {
    findings.push(
      Finding.fromObject({
        name: "Timelock Operation Cancelled",
        description: "A timelock operation was cancelled",
        alertId: "PIL-TIMELOCK-CANCELLED",
        severity: FindingSeverity.Medium,
        type: FindingType.Suspicious,
        metadata: {
          operationId: event.args[0],
          txHash: txEvent.hash,
        },
      })
    );
  }

  return findings;
}

/**
 * Detect high-volume activity patterns
 */
function detectHighVolumeActivity(txEvent: TransactionEvent): Finding[] {
  const findings: Finding[] = [];
  const blockNumber = txEvent.blockNumber;

  // Track container creations
  const containerEvents = txEvent.filterLog(EVENTS.CONTAINER_CREATED);
  if (containerEvents.length > 0) {
    const key = `container-${txEvent.from}`;
    const timestamps = activityTracker.get(key) || [];
    timestamps.push(blockNumber);
    
    // Keep only last 100 entries
    if (timestamps.length > 100) {
      timestamps.shift();
    }
    activityTracker.set(key, timestamps);

    // Check for rapid activity
    const recentCount = timestamps.filter(
      (t) => t >= blockNumber - 10
    ).length;
    
    if (recentCount >= THRESHOLDS.RAPID_CONTAINER_CREATION) {
      findings.push(
        Finding.fromObject({
          name: "High Volume Container Creation",
          description: `Address ${txEvent.from} created ${recentCount} containers in 10 blocks`,
          alertId: "PIL-HIGH-VOLUME",
          severity: FindingSeverity.Medium,
          type: FindingType.Suspicious,
          metadata: {
            address: txEvent.from,
            count: recentCount.toString(),
            txHash: txEvent.hash,
          },
        })
      );
    }
  }

  return findings;
}

/**
 * Detect role changes
 */
function detectRoleChanges(txEvent: TransactionEvent): Finding[] {
  const findings: Finding[] = [];

  const grantedEvents = txEvent.filterLog(EVENTS.ROLE_GRANTED);
  const revokedEvents = txEvent.filterLog(EVENTS.ROLE_REVOKED);

  for (const event of grantedEvents) {
    findings.push(
      Finding.fromObject({
        name: "PIL Role Granted",
        description: `Role ${event.args[0]} granted to ${event.args[1]}`,
        alertId: "PIL-ROLE-GRANTED",
        severity: FindingSeverity.High,
        type: FindingType.Info,
        metadata: {
          role: event.args[0],
          account: event.args[1],
          sender: event.args[2],
          contract: event.address,
          txHash: txEvent.hash,
        },
      })
    );
  }

  for (const event of revokedEvents) {
    findings.push(
      Finding.fromObject({
        name: "PIL Role Revoked",
        description: `Role ${event.args[0]} revoked from ${event.args[1]}`,
        alertId: "PIL-ROLE-REVOKED",
        severity: FindingSeverity.High,
        type: FindingType.Info,
        metadata: {
          role: event.args[0],
          account: event.args[1],
          sender: event.args[2],
          contract: event.address,
          txHash: txEvent.hash,
        },
      })
    );
  }

  return findings;
}

/**
 * Detect potential double-spend attempts
 */
function detectDoubleSpendAttempts(txEvent: TransactionEvent): Finding[] {
  const findings: Finding[] = [];

  // Check for reverted nullifier consumptions (potential double-spend)
  if (txEvent.status === false) {
    const nullifierConsumptions = txEvent.filterLog(EVENTS.NULLIFIER_CONSUMED);
    const containerConsumptions = txEvent.filterLog(EVENTS.CONTAINER_CONSUMED);

    if (nullifierConsumptions.length > 0 || containerConsumptions.length > 0) {
      findings.push(
        Finding.fromObject({
          name: "Potential Double-Spend Attempt",
          description: "A transaction attempting nullifier/container consumption reverted",
          alertId: "PIL-DOUBLE-SPEND-ATTEMPT",
          severity: FindingSeverity.Critical,
          type: FindingType.Exploit,
          metadata: {
            from: txEvent.from,
            txHash: txEvent.hash,
            nullifierAttempts: nullifierConsumptions.length.toString(),
            containerAttempts: containerConsumptions.length.toString(),
          },
        })
      );
    }
  }

  return findings;
}

/**
 * Detect suspicious gas usage
 */
function detectSuspiciousGas(txEvent: TransactionEvent): Finding[] {
  const findings: Finding[] = [];

  if (txEvent.gasLimit && txEvent.gasLimit > THRESHOLDS.HIGH_GAS_LIMIT) {
    findings.push(
      Finding.fromObject({
        name: "High Gas Limit Transaction",
        description: `Transaction with unusually high gas limit: ${txEvent.gasLimit}`,
        alertId: "PIL-HIGH-GAS",
        severity: FindingSeverity.Low,
        type: FindingType.Suspicious,
        metadata: {
          from: txEvent.from,
          gasLimit: txEvent.gasLimit.toString(),
          txHash: txEvent.hash,
        },
      })
    );
  }

  return findings;
}

export default {
  handleTransaction,
};
