import {
  ContainerCreated,
  ContainerConsumed,
} from "../generated/ProofCarryingContainer/ProofCarryingContainer";
import {
  Container,
  User,
  SystemStats,
} from "../generated/schema";
import { BigInt, Bytes } from "@graphprotocol/graph-ts";

// Helper: Get or create User entity
function getOrCreateUser(address: Bytes, timestamp: BigInt): User {
  let userId = address.toHexString();
  let user = User.load(userId);
  if (!user) {
    user = new User(userId);
    user.totalOperations = BigInt.fromI32(0);
    user.successfulOperations = BigInt.fromI32(0);
    user.failedOperations = BigInt.fromI32(0);
    user.firstOperationAt = timestamp;
    user.lastOperationAt = timestamp;
    user.containersCreated = [];
  }
  user.lastOperationAt = timestamp;
  return user;
}

// Helper: Get or create SystemStats singleton
function getOrCreateSystemStats(): SystemStats {
  let stats = SystemStats.load("stats");
  if (!stats) {
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

// Event handler: ContainerCreated
export function handleContainerCreated(event: ContainerCreated): void {
  let containerId = event.params.containerId.toHexString();
  
  // Create container entity
  let container = new Container(containerId);
  container.stateCommitment = event.params.stateCommitment;
  container.nullifier = event.params.nullifier;
  container.chainId = BigInt.fromI32(1); // Default to mainnet
  container.createdAt = event.block.timestamp;
  container.blockNumber = event.block.number;
  container.transactionHash = event.transaction.hash;
  container.creator = event.transaction.from;
  container.isVerified = false;
  container.isConsumed = false;
  container.save();
  
  // Update user stats
  let user = getOrCreateUser(event.transaction.from, event.block.timestamp);
  let createdContainers = user.containersCreated;
  createdContainers.push(containerId);
  user.containersCreated = createdContainers;
  user.totalOperations = user.totalOperations.plus(BigInt.fromI32(1));
  user.successfulOperations = user.successfulOperations.plus(BigInt.fromI32(1));
  user.save();
  
  // Update system stats
  let stats = getOrCreateSystemStats();
  stats.totalContainers = stats.totalContainers.plus(BigInt.fromI32(1));
  stats.totalOperations = stats.totalOperations.plus(BigInt.fromI32(1));
  stats.successfulOperations = stats.successfulOperations.plus(BigInt.fromI32(1));
  stats.lastUpdated = event.block.timestamp;
  stats.save();
}

// Event handler: ContainerConsumed
export function handleContainerConsumed(event: ContainerConsumed): void {
  let containerId = event.params.containerId.toHexString();
  
  let container = Container.load(containerId);
  if (container) {
    container.isConsumed = true;
    container.consumedAt = event.block.timestamp;
    container.consumer = event.transaction.from;
    container.save();
    
    // Update user stats
    let user = getOrCreateUser(event.transaction.from, event.block.timestamp);
    user.totalOperations = user.totalOperations.plus(BigInt.fromI32(1));
    user.successfulOperations = user.successfulOperations.plus(BigInt.fromI32(1));
    user.save();
    
    // Update system stats
    let stats = getOrCreateSystemStats();
    stats.totalConsumed = stats.totalConsumed.plus(BigInt.fromI32(1));
    stats.totalNullifiers = stats.totalNullifiers.plus(BigInt.fromI32(1));
    stats.totalOperations = stats.totalOperations.plus(BigInt.fromI32(1));
    stats.successfulOperations = stats.successfulOperations.plus(BigInt.fromI32(1));
    stats.lastUpdated = event.block.timestamp;
    stats.save();
  }
}
