import { BigInt, Bytes } from "@graphprotocol/graph-ts";
import {
  CommitmentCreated,
  CommitmentFinalized,
} from "../generated/ExecutionAgnosticStateCommitments/ExecutionAgnosticStateCommitments";
import { StateCommitment, StateTransition, SystemStats } from "../generated/schema";

/**
 * Get or create system stats singleton
 */
function getOrCreateStats(): SystemStats {
  let stats = SystemStats.load("stats");
  if (stats == null) {
    stats = new SystemStats("stats");
    stats.totalContainers = BigInt.fromI32(0);
    stats.totalVerified = BigInt.fromI32(0);
    stats.totalConsumed = BigInt.fromI32(0);
    stats.totalPolicies = BigInt.fromI32(0);
    stats.activePolicies = BigInt.fromI32(0);
    stats.totalCommitments = BigInt.fromI32(0);
    stats.totalNullifiers = BigInt.fromI32(0);
    stats.totalOperations = BigInt.fromI32(0);
    stats.successfulOperations = BigInt.fromI32(0);
    stats.totalUsers = BigInt.fromI32(0);
    stats.lastUpdated = BigInt.fromI32(0);
  }
  return stats;
}

/**
 * Handle CommitmentCreated event
 */
export function handleCommitmentCreated(event: CommitmentCreated): void {
  let commitment = new StateCommitment(event.params.commitmentId.toHexString());
  
  commitment.stateRoot = event.params.stateHash;
  commitment.executionEnvHash = event.params.nullifier;
  commitment.creator = event.params.creator;
  commitment.createdAt = event.block.timestamp;
  commitment.lastUpdated = event.block.timestamp;
  commitment.transitionCount = BigInt.fromI32(0);
  commitment.blockNumber = event.block.number;
  
  commitment.save();
  
  // Update stats
  let stats = getOrCreateStats();
  stats.totalCommitments = stats.totalCommitments.plus(BigInt.fromI32(1));
  stats.lastUpdated = event.block.timestamp;
  stats.save();
}

/**
 * Handle CommitmentFinalized event
 */
export function handleCommitmentFinalized(event: CommitmentFinalized): void {
  let commitment = StateCommitment.load(event.params.commitmentId.toHexString());
  if (commitment == null) {
    return;
  }
  
  commitment.lastUpdated = event.block.timestamp;
  commitment.transitionCount = event.params.attestationCount;
  commitment.save();
}
