import { BigInt, Bytes } from "@graphprotocol/graph-ts";
import {
  NullifierConsumed,
  DomainRegistered,
  CrossDomainLink,
} from "../generated/CrossDomainNullifierAlgebra/CrossDomainNullifierAlgebra";
import {
  NullifierConsumption,
  NullifierRelay,
  Domain,
  SystemStats,
} from "../generated/schema";

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
 * Get or create domain entity
 */
function getOrCreateDomain(domainId: Bytes): Domain {
  let domain = Domain.load(domainId.toHexString());
  if (domain == null) {
    domain = new Domain(domainId.toHexString());
    domain.name = "Unknown";
    domain.registeredAt = BigInt.fromI32(0);
    domain.blockNumber = BigInt.fromI32(0);
    domain.totalNullifiers = BigInt.fromI32(0);
  }
  return domain;
}

/**
 * Handle NullifierConsumed event
 */
export function handleNullifierConsumed(event: NullifierConsumed): void {
  let nullifier = new NullifierConsumption(event.params.nullifier.toHexString());
  
  nullifier.nullifier = event.params.nullifier;
  nullifier.domainId = BigInt.fromI32(0);
  nullifier.consumer = event.params.consumer;
  nullifier.consumedAt = event.block.timestamp;
  nullifier.blockNumber = event.block.number;
  nullifier.transactionHash = event.transaction.hash;
  nullifier.isRelayed = false;
  
  nullifier.save();
  
  // Update domain stats
  let domain = getOrCreateDomain(event.params.domainId);
  domain.totalNullifiers = domain.totalNullifiers.plus(BigInt.fromI32(1));
  domain.save();
  
  // Update global stats
  let stats = getOrCreateStats();
  stats.totalNullifiers = stats.totalNullifiers.plus(BigInt.fromI32(1));
  stats.lastUpdated = event.block.timestamp;
  stats.save();
}

/**
 * Handle DomainRegistered event
 */
export function handleDomainRegistered(event: DomainRegistered): void {
  let domain = getOrCreateDomain(event.params.domainId);
  
  domain.name = event.params.chainId.toString();
  domain.registeredAt = event.block.timestamp;
  domain.blockNumber = event.block.number;
  
  domain.save();
}

/**
 * Handle CrossDomainLink event
 */
export function handleCrossDomainLink(event: CrossDomainLink): void {
  // Update nullifier as relayed
  let nullifier = NullifierConsumption.load(event.params.parentNullifier.toHexString());
  if (nullifier != null) {
    nullifier.isRelayed = true;
    nullifier.save();
  }
  
  // Create relay record
  let relayId = event.params.parentNullifier.toHexString()
    .concat("-")
    .concat(event.block.timestamp.toString());
    
  let relay = new NullifierRelay(relayId);
  
  relay.nullifier = event.params.parentNullifier.toHexString();
  relay.sourceDomain = BigInt.fromI32(0);
  relay.targetDomain = BigInt.fromI32(0);
  relay.timestamp = event.block.timestamp;
  relay.blockNumber = event.block.number;
  
  relay.save();
}
