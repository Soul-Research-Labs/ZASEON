import {
  BigInt,
  Bytes,
  Address
} from "@graphprotocol/graph-ts"

import {
  LockCreated,
  LockUnlocked,
  OptimisticUnlockInitiated,
  OptimisticUnlockFinalized,
  LockDisputed,
  DomainRegistered,
  VerifierRegistered
} from "../generated/ZKBoundStateLocks/ZKBoundStateLocks"

import {
  ZKSLock,
  ZKSLockDomain,
  ZKSLockOptimisticUnlock,
  ZKSLockUnlockReceipt,
  ZKSLockStats
} from "../generated/schema"

// ============================================================================
// Helper Functions
// ============================================================================

function getOrCreateStats(): ZKSLockStats {
  let stats = ZKSLockStats.load("zkslocks-stats")
  if (stats == null) {
    stats = new ZKSLockStats("zkslocks-stats")
    stats.totalLocks = BigInt.fromI32(0)
    stats.activeLocks = BigInt.fromI32(0)
    stats.totalUnlocks = BigInt.fromI32(0)
    stats.totalOptimisticUnlocks = BigInt.fromI32(0)
    stats.totalChallenges = BigInt.fromI32(0)
    stats.totalDomains = BigInt.fromI32(0)
    stats.totalBondedValue = BigInt.fromI32(0)
    stats.lastUpdated = BigInt.fromI32(0)
  }
  return stats
}

// ============================================================================
// Event Handlers
// ============================================================================

export function handleLockCreated(event: LockCreated): void {
  let lockId = event.params.lockId.toHexString()
  
  let lock = new ZKSLock(lockId)
  lock.stateCommitment = event.params.oldStateCommitment
  lock.transitionPredicateHash = event.params.transitionPredicateHash
  lock.policyBinding = event.params.policyHash
  lock.verifier = event.params.lockedBy
  lock.creator = event.params.lockedBy
  lock.isLocked = true
  lock.createdAt = event.block.timestamp
  lock.blockNumber = event.block.number
  lock.transactionHash = event.transaction.hash
  lock.commitmentChain = [event.params.oldStateCommitment]
  lock.save()

  let stats = getOrCreateStats()
  stats.totalLocks = stats.totalLocks.plus(BigInt.fromI32(1))
  stats.activeLocks = stats.activeLocks.plus(BigInt.fromI32(1))
  stats.lastUpdated = event.block.timestamp
  stats.save()
}

export function handleLockUnlocked(event: LockUnlocked): void {
  let lockId = event.params.lockId.toHexString()
  
  let lock = ZKSLock.load(lockId)
  if (lock != null) {
    let previousState = lock.stateCommitment
    
    lock.isLocked = false
    lock.unlockedAt = event.block.timestamp
    lock.unlockTxHash = event.transaction.hash
    lock.stateCommitment = event.params.newStateCommitment
    
    let chain = lock.commitmentChain
    chain.push(event.params.newStateCommitment)
    lock.commitmentChain = chain
    lock.save()

    let receiptId = lockId + "-" + event.block.timestamp.toString()
    let receipt = new ZKSLockUnlockReceipt(receiptId)
    receipt.lock = lock.id
    receipt.previousState = previousState
    receipt.newState = event.params.newStateCommitment
    receipt.nullifier = event.params.nullifier
    receipt.transitionPredicate = lock.transitionPredicateHash
    receipt.policyEnforced = lock.policyBinding
    receipt.unlocker = event.params.unlockedBy
    receipt.proofHash = event.transaction.hash
    receipt.timestamp = event.block.timestamp
    receipt.blockNumber = event.block.number
    receipt.transactionHash = event.transaction.hash
    receipt.save()

    let stats = getOrCreateStats()
    stats.totalUnlocks = stats.totalUnlocks.plus(BigInt.fromI32(1))
    stats.activeLocks = stats.activeLocks.minus(BigInt.fromI32(1))
    stats.lastUpdated = event.block.timestamp
    stats.save()
  }
}

export function handleOptimisticUnlockInitiated(event: OptimisticUnlockInitiated): void {
  let lockId = event.params.lockId.toHexString()
  let optimisticId = lockId + "-" + event.params.unlocker.toHexString() + "-" + event.block.timestamp.toString()
  
  let optimistic = new ZKSLockOptimisticUnlock(optimisticId)
  optimistic.lock = lockId
  optimistic.proposer = event.params.unlocker
  optimistic.proposedNewState = event.params.lockId
  optimistic.bondAmount = event.params.bondAmount
  optimistic.disputeDeadline = event.params.finalizeAfter
  optimistic.isFinalized = false
  optimistic.isChallenged = false
  optimistic.proposedAt = event.block.timestamp
  optimistic.blockNumber = event.block.number
  optimistic.save()

  let lock = ZKSLock.load(lockId)
  if (lock != null) {
    lock.optimisticUnlock = optimistic.id
    lock.save()
  }

  let stats = getOrCreateStats()
  stats.totalOptimisticUnlocks = stats.totalOptimisticUnlocks.plus(BigInt.fromI32(1))
  stats.totalBondedValue = stats.totalBondedValue.plus(event.params.bondAmount)
  stats.lastUpdated = event.block.timestamp
  stats.save()
}

export function handleOptimisticUnlockFinalized(event: OptimisticUnlockFinalized): void {
  let lockId = event.params.lockId.toHexString()
  
  let lock = ZKSLock.load(lockId)
  if (lock != null && lock.optimisticUnlock != null) {
    let optimistic = ZKSLockOptimisticUnlock.load(lock.optimisticUnlock!)
    if (optimistic != null) {
      optimistic.isFinalized = true
      optimistic.finalizedAt = event.block.timestamp
      optimistic.save()

      let stats = getOrCreateStats()
      stats.totalBondedValue = stats.totalBondedValue.minus(optimistic.bondAmount)
      stats.activeLocks = stats.activeLocks.minus(BigInt.fromI32(1))
      stats.lastUpdated = event.block.timestamp
      stats.save()
    }

    lock.isLocked = false
    lock.unlockedAt = event.block.timestamp
    lock.save()
  }
}

export function handleLockDisputed(event: LockDisputed): void {
  let lockId = event.params.lockId.toHexString()
  
  let lock = ZKSLock.load(lockId)
  if (lock != null && lock.optimisticUnlock != null) {
    let optimistic = ZKSLockOptimisticUnlock.load(lock.optimisticUnlock!)
    if (optimistic != null) {
      optimistic.isChallenged = true
      optimistic.challenger = event.params.disputer
      optimistic.challengedAt = event.block.timestamp
      optimistic.save()

      let stats = getOrCreateStats()
      stats.totalChallenges = stats.totalChallenges.plus(BigInt.fromI32(1))
      stats.totalBondedValue = stats.totalBondedValue.minus(optimistic.bondAmount)
      stats.lastUpdated = event.block.timestamp
      stats.save()
    }
  }
}

export function handleDomainRegistered(event: DomainRegistered): void {
  let domainId = event.params.domainSeparator.toHexString()
  
  let domain = new ZKSLockDomain(domainId)
  domain.name = event.params.name
  domain.chainId = BigInt.fromI32(event.params.chainId)
  domain.appId = BigInt.fromI32(event.params.appId)
  domain.currentEpoch = event.params.epoch
  domain.domainSeparator = event.params.domainSeparator
  domain.isActive = true
  domain.registeredAt = event.block.timestamp
  domain.blockNumber = event.block.number
  domain.save()

  let stats = getOrCreateStats()
  stats.totalDomains = stats.totalDomains.plus(BigInt.fromI32(1))
  stats.lastUpdated = event.block.timestamp
  stats.save()
}

export function handleVerifierRegistered(event: VerifierRegistered): void {
  let stats = getOrCreateStats()
  stats.lastUpdated = event.block.timestamp
  stats.save()
}
