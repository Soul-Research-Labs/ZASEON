import { BigInt, Bytes } from "@graphprotocol/graph-ts";
import {
  CoordinatedTransitionCreated,
  CoordinatedTransitionCompleted,
  CrossChainTransferInitiated,
} from "../generated/PILv2Orchestrator/PILv2Orchestrator";
import {
  Operation,
  User,
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
 * Get or create user entity
 */
function getOrCreateUser(address: Bytes, timestamp: BigInt): User {
  let userId = address.toHexString();
  let user = User.load(userId);
  if (user == null) {
    user = new User(userId);
    user.totalOperations = BigInt.fromI32(0);
    user.successfulOperations = BigInt.fromI32(0);
    user.failedOperations = BigInt.fromI32(0);
    user.containersCreated = [];
    user.firstOperationAt = timestamp;
    
    // Update stats
    let stats = getOrCreateStats();
    stats.totalUsers = stats.totalUsers.plus(BigInt.fromI32(1));
    stats.save();
  }
  return user;
}

/**
 * Handle CoordinatedTransitionCreated event
 */
export function handleCoordinatedTransitionCreated(event: CoordinatedTransitionCreated): void {
  let operation = new Operation(event.params.transitionId.toHexString());
  
  // Get or create user from transaction sender
  let user = getOrCreateUser(event.transaction.from, event.block.timestamp);
  
  operation.user = user.id;
  operation.success = true;
  operation.message = "Coordinated transition created";
  operation.timestamp = event.block.timestamp;
  operation.blockNumber = event.block.number;
  operation.transactionHash = event.transaction.hash;
  
  operation.save();
  
  // Update user stats
  user.totalOperations = user.totalOperations.plus(BigInt.fromI32(1));
  user.successfulOperations = user.successfulOperations.plus(BigInt.fromI32(1));
  user.lastOperationAt = event.block.timestamp;
  user.save();
  
  // Update global stats
  let stats = getOrCreateStats();
  stats.totalOperations = stats.totalOperations.plus(BigInt.fromI32(1));
  stats.successfulOperations = stats.successfulOperations.plus(BigInt.fromI32(1));
  stats.lastUpdated = event.block.timestamp;
  stats.save();
}

/**
 * Handle CoordinatedTransitionCompleted event
 */
export function handleCoordinatedTransitionCompleted(event: CoordinatedTransitionCompleted): void {
  let operation = Operation.load(event.params.transitionId.toHexString());
  if (operation == null) {
    return;
  }
  
  operation.message = "Coordinated transition completed";
  operation.save();
}

/**
 * Handle CrossChainTransferInitiated event
 */
export function handleCrossChainTransferInitiated(event: CrossChainTransferInitiated): void {
  let operationId = event.params.containerId.toHexString()
    .concat("-")
    .concat(event.block.timestamp.toString());
    
  let operation = new Operation(operationId);
  
  // Get or create user from transaction sender
  let user = getOrCreateUser(event.transaction.from, event.block.timestamp);
  
  operation.user = user.id;
  operation.success = true;
  operation.message = "Cross-chain transfer initiated";
  operation.timestamp = event.block.timestamp;
  operation.blockNumber = event.block.number;
  operation.transactionHash = event.transaction.hash;
  
  operation.save();
  
  // Update user stats
  user.totalOperations = user.totalOperations.plus(BigInt.fromI32(1));
  user.successfulOperations = user.successfulOperations.plus(BigInt.fromI32(1));
  user.lastOperationAt = event.block.timestamp;
  user.save();
  
  // Update global stats
  let stats = getOrCreateStats();
  stats.totalOperations = stats.totalOperations.plus(BigInt.fromI32(1));
  stats.successfulOperations = stats.successfulOperations.plus(BigInt.fromI32(1));
  stats.lastUpdated = event.block.timestamp;
  stats.save();
}
