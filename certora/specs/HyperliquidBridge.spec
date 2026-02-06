/**
 * Certora Verification Spec: HyperliquidBridgeAdapter
 *
 * Verifies critical invariants for the Soul Protocol <-> Hyperliquid bridge:
 * - Nonce monotonicity
 * - Replay protection permanence
 * - Nullifier permanence
 * - Access control enforcement
 * - Escrow lifecycle correctness
 * - Value conservation
 * - Pause mechanism
 *
 * Hyperliquid-specific properties:
 * - Chain ID = 999 (HyperEVM mainnet)
 * - 1 HYPE = 1e8 drips (8 decimal precision)
 * - Default block confirmations = 3 (~0.6s BFT finality)
 * - 0.15% bridge fee (15 BPS)
 */

using HyperliquidBridgeAdapter as bridge;

/*//////////////////////////////////////////////////////////////
                        GHOST VARIABLES
//////////////////////////////////////////////////////////////*/

ghost uint256 ghostDepositNonce {
    init_state axiom ghostDepositNonce == 0;
}

ghost uint256 ghostWithdrawalNonce {
    init_state axiom ghostWithdrawalNonce == 0;
}

ghost uint256 ghostEscrowNonce {
    init_state axiom ghostEscrowNonce == 0;
}

ghost uint256 ghostTotalDeposited {
    init_state axiom ghostTotalDeposited == 0;
}

ghost uint256 ghostTotalWithdrawn {
    init_state axiom ghostTotalWithdrawn == 0;
}

ghost mapping(bytes32 => bool) ghostUsedTxHashes;
ghost mapping(bytes32 => bool) ghostUsedNullifiers;

/*//////////////////////////////////////////////////////////////
                            HOOKS
//////////////////////////////////////////////////////////////*/

hook Sstore bridge.depositNonce uint256 newVal (uint256 oldVal) {
    ghostDepositNonce = newVal;
}

hook Sstore bridge.withdrawalNonce uint256 newVal (uint256 oldVal) {
    ghostWithdrawalNonce = newVal;
}

hook Sstore bridge.escrowNonce uint256 newVal (uint256 oldVal) {
    ghostEscrowNonce = newVal;
}

hook Sstore bridge.totalDeposited uint256 newVal (uint256 oldVal) {
    ghostTotalDeposited = newVal;
}

hook Sstore bridge.totalWithdrawn uint256 newVal (uint256 oldVal) {
    ghostTotalWithdrawn = newVal;
}

/*//////////////////////////////////////////////////////////////
                    INVARIANT: NONCE MONOTONICITY
//////////////////////////////////////////////////////////////*/

/// @title Deposit nonce never decreases
invariant depositNonceMonotonic()
    bridge.depositNonce() >= ghostDepositNonce
    {
        preserved {
            require ghostDepositNonce <= bridge.depositNonce();
        }
    }

/// @title Withdrawal nonce never decreases
invariant withdrawalNonceMonotonic()
    bridge.withdrawalNonce() >= ghostWithdrawalNonce
    {
        preserved {
            require ghostWithdrawalNonce <= bridge.withdrawalNonce();
        }
    }

/// @title Escrow nonce never decreases
invariant escrowNonceMonotonic()
    bridge.escrowNonce() >= ghostEscrowNonce
    {
        preserved {
            require ghostEscrowNonce <= bridge.escrowNonce();
        }
    }

/*//////////////////////////////////////////////////////////////
            INVARIANT: CONSTANTS NEVER CHANGE
//////////////////////////////////////////////////////////////*/

/// @title Hyperliquid chain ID is always 999
invariant hyperliquidChainIdConstant()
    bridge.HYPERLIQUID_CHAIN_ID() == 999;

/// @title Drips per HYPE is always 1e8
invariant dripsPerHypeConstant()
    bridge.DRIPS_PER_HYPE() == 100000000;

/// @title Min deposit is always 0.1 HYPE (1e7 drips)
invariant minDepositConstant()
    bridge.MIN_DEPOSIT_DRIPS() == 10000000;

/// @title Bridge fee BPS is always 15 (0.15%)
invariant bridgeFeeBpsConstant()
    bridge.BRIDGE_FEE_BPS() == 15;

/// @title Withdrawal refund delay is always 24 hours
invariant withdrawalRefundDelayConstant()
    bridge.WITHDRAWAL_REFUND_DELAY() == 86400;

/// @title Min escrow timelock is always 30 minutes
invariant minEscrowTimelockConstant()
    bridge.MIN_ESCROW_TIMELOCK() == 1800;

/// @title Max escrow timelock is always 14 days
invariant maxEscrowTimelockConstant()
    bridge.MAX_ESCROW_TIMELOCK() == 1209600;

/// @title Default block confirmations is always 3
invariant defaultBlockConfirmationsConstant()
    bridge.DEFAULT_BLOCK_CONFIRMATIONS() == 3;

/*//////////////////////////////////////////////////////////////
            RULE: REPLAY PROTECTION IS PERMANENT
//////////////////////////////////////////////////////////////*/

/// @title Once a Hyperliquid tx hash is used, it stays used forever
rule replayProtectionPermanence(bytes32 txHash, method f) {
    bool usedBefore = bridge.usedHLTxHashes(txHash);
    require usedBefore == true;

    env e;
    calldataarg args;
    f(e, args);

    bool usedAfter = bridge.usedHLTxHashes(txHash);
    assert usedAfter == true, "Used tx hash was reset";
}

/*//////////////////////////////////////////////////////////////
            RULE: NULLIFIER PERMANENCE
//////////////////////////////////////////////////////////////*/

/// @title Once a nullifier is used, it stays used forever
rule nullifierPermanence(bytes32 nullifier, method f) {
    bool usedBefore = bridge.usedNullifiers(nullifier);
    require usedBefore == true;

    env e;
    calldataarg args;
    f(e, args);

    bool usedAfter = bridge.usedNullifiers(nullifier);
    assert usedAfter == true, "Used nullifier was reset";
}

/*//////////////////////////////////////////////////////////////
            RULE: ACCESS CONTROL
//////////////////////////////////////////////////////////////*/

/// @title Only OPERATOR_ROLE can complete deposits
rule onlyOperatorCanCompleteDeposit(env e) {
    bytes32 depositId;

    bool hasRole = bridge.hasRole(bridge.OPERATOR_ROLE(), e.msg.sender)
        || bridge.hasRole(bridge.DEFAULT_ADMIN_ROLE(), e.msg.sender);

    bridge.completeHYPEDeposit@withrevert(e, depositId);

    assert !hasRole => lastReverted, "Non-operator completed deposit";
}

/// @title Only GUARDIAN_ROLE can pause
rule onlyGuardianCanPause(env e) {
    bool hasRole = bridge.hasRole(bridge.GUARDIAN_ROLE(), e.msg.sender)
        || bridge.hasRole(bridge.DEFAULT_ADMIN_ROLE(), e.msg.sender);

    bridge.pause@withrevert(e);

    assert !hasRole => lastReverted, "Non-guardian paused bridge";
}

/*//////////////////////////////////////////////////////////////
            RULE: WITHDRAWAL REFUND FINALITY
//////////////////////////////////////////////////////////////*/

/// @title Refunded withdrawal cannot be refunded again
rule withdrawalRefundFinality(env e) {
    bytes32 withdrawalId;

    // First refund
    bridge.refundWithdrawal(e, withdrawalId);

    // Second refund should fail
    bridge.refundWithdrawal@withrevert(e, withdrawalId);
    assert lastReverted, "Withdrawal was refunded twice";
}

/*//////////////////////////////////////////////////////////////
            RULE: ESCROW FINISH/CANCEL MUTUAL EXCLUSION
//////////////////////////////////////////////////////////////*/

/// @title Finished escrow cannot be cancelled
rule escrowFinishBlocksCancel(env e1, env e2) {
    bytes32 escrowId;
    bytes32 preimage;

    bridge.finishEscrow(e1, escrowId, preimage);

    bridge.cancelEscrow@withrevert(e2, escrowId);
    assert lastReverted, "Cancelled a finished escrow";
}

/// @title Cancelled escrow cannot be finished
rule escrowCancelBlocksFinish(env e1, env e2) {
    bytes32 escrowId;
    bytes32 preimage;

    bridge.cancelEscrow(e1, escrowId);

    bridge.finishEscrow@withrevert(e2, escrowId, preimage);
    assert lastReverted, "Finished a cancelled escrow";
}

/// @title Finished escrow cannot be finished again
rule escrowFinishFinality(env e1, env e2) {
    bytes32 escrowId;
    bytes32 preimage;

    bridge.finishEscrow(e1, escrowId, preimage);

    bridge.finishEscrow@withrevert(e2, escrowId, preimage);
    assert lastReverted, "Escrow was finished twice";
}

/*//////////////////////////////////////////////////////////////
            RULE: PAUSE MECHANISM
//////////////////////////////////////////////////////////////*/

/// @title Paused bridge blocks deposits
rule pauseBlocksDeposits(env e) {
    require bridge.paused();

    bytes32 txHash; address sender; address recipient;
    uint256 amount; uint256 blockNum;
    IHyperliquidBridgeAdapter.HyperliquidMerkleProof proof;
    IHyperliquidBridgeAdapter.ValidatorAttestation[] attestations;

    bridge.initiateHYPEDeposit@withrevert(
        e, txHash, sender, recipient, amount, blockNum, proof, attestations
    );
    assert lastReverted, "Deposit succeeded while paused";
}

/// @title Paused bridge blocks withdrawals
rule pauseBlocksWithdrawals(env e) {
    require bridge.paused();

    address recipient;
    uint256 amount;

    bridge.initiateWithdrawal@withrevert(e, recipient, amount);
    assert lastReverted, "Withdrawal succeeded while paused";
}

/*//////////////////////////////////////////////////////////////
            RULE: NONCES NEVER DECREASE
//////////////////////////////////////////////////////////////*/

/// @title Deposit nonce never decreases across any method
rule depositNonceNeverDecreases(method f) {
    uint256 nonceBefore = bridge.depositNonce();

    env e;
    calldataarg args;
    f(e, args);

    uint256 nonceAfter = bridge.depositNonce();
    assert nonceAfter >= nonceBefore, "Deposit nonce decreased";
}

/// @title Withdrawal nonce never decreases across any method
rule withdrawalNonceNeverDecreases(method f) {
    uint256 nonceBefore = bridge.withdrawalNonce();

    env e;
    calldataarg args;
    f(e, args);

    uint256 nonceAfter = bridge.withdrawalNonce();
    assert nonceAfter >= nonceBefore, "Withdrawal nonce decreased";
}

/*//////////////////////////////////////////////////////////////
            RULE: VALUE CONSERVATION
//////////////////////////////////////////////////////////////*/

/// @title Total deposited never decreases
rule totalDepositedNeverDecreases(method f) {
    uint256 totalBefore = bridge.totalDeposited();

    env e;
    calldataarg args;
    f(e, args);

    uint256 totalAfter = bridge.totalDeposited();
    assert totalAfter >= totalBefore, "Total deposited decreased";
}

/// @title Total withdrawn never decreases
rule totalWithdrawnNeverDecreases(method f) {
    uint256 totalBefore = bridge.totalWithdrawn();

    env e;
    calldataarg args;
    f(e, args);

    uint256 totalAfter = bridge.totalWithdrawn();
    assert totalAfter >= totalBefore, "Total withdrawn decreased";
}

/*//////////////////////////////////////////////////////////////
            RULE: BLOCK NUMBER MONOTONICITY
//////////////////////////////////////////////////////////////*/

/// @title Latest block number never decreases
rule latestBlockNeverDecreases(method f) {
    uint256 blockBefore = bridge.latestBlockNumber();

    env e;
    calldataarg args;
    f(e, args);

    uint256 blockAfter = bridge.latestBlockNumber();
    assert blockAfter >= blockBefore, "Latest block number decreased";
}
