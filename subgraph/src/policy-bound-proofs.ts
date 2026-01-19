import { BigInt, Bytes } from "@graphprotocol/graph-ts";
import {
  PolicyRegistered,
  PolicyDeactivated,
  ProofVerified,
} from "../generated/PolicyBoundProofs/PolicyBoundProofs";
import { PolicyDefinition, ComplianceProof, SystemStats } from "../generated/schema";

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
 * Handle PolicyRegistered event
 */
export function handlePolicyRegistered(event: PolicyRegistered): void {
  let policy = new PolicyDefinition(event.params.policyId.toHexString());
  
  policy.policyType = event.params.policyHash;
  policy.creator = Bytes.empty();
  policy.threshold = BigInt.fromI32(0);
  policy.isActive = true;
  policy.createdAt = event.block.timestamp;
  policy.blockNumber = event.block.number;
  
  policy.save();
  
  // Update stats
  let stats = getOrCreateStats();
  stats.totalPolicies = stats.totalPolicies.plus(BigInt.fromI32(1));
  stats.activePolicies = stats.activePolicies.plus(BigInt.fromI32(1));
  stats.lastUpdated = event.block.timestamp;
  stats.save();
}

/**
 * Handle PolicyDeactivated event
 */
export function handlePolicyDeactivated(event: PolicyDeactivated): void {
  let policy = PolicyDefinition.load(event.params.policyId.toHexString());
  if (policy == null) {
    return;
  }
  
  policy.isActive = false;
  policy.save();
  
  // Update stats
  let stats = getOrCreateStats();
  stats.activePolicies = stats.activePolicies.minus(BigInt.fromI32(1));
  stats.lastUpdated = event.block.timestamp;
  stats.save();
}

/**
 * Handle ProofVerified event
 */
export function handleProofVerified(event: ProofVerified): void {
  let proofId = event.params.proofHash.toHexString()
    .concat("-")
    .concat(event.params.verifier.toHexString())
    .concat("-")
    .concat(event.block.timestamp.toString());
    
  let proof = new ComplianceProof(proofId);
  
  proof.policy = event.params.policyHash.toHexString();
  proof.subject = event.params.verifier;
  proof.compliant = event.params.success;
  proof.timestamp = event.block.timestamp;
  proof.blockNumber = event.block.number;
  
  proof.save();
}
