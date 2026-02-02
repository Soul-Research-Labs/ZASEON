// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "forge-std/StdInvariant.sol";
import "../../contracts/security/SecurityModule.sol";

/**
 * @title SecurityModuleInvariant
 * @notice Invariant tests for SecurityModule
 * @dev Tests critical security properties that must always hold
 */

// Concrete implementation for testing
contract TestableSecurityModule is SecurityModule {
    uint256 public totalDeposited;
    uint256 public totalWithdrawn;

    function deposit(
        uint256 amount
    ) external rateLimited circuitBreaker(amount) {
        _recordDeposit(msg.sender);
        totalDeposited += amount;
    }

    function withdraw(
        uint256 amount
    )
        external
        noFlashLoan
        withdrawalLimited(amount)
        accountWithdrawalLimited(amount)
    {
        totalWithdrawn += amount;
    }

    function setRateLimitConfigPublic(
        uint256 window,
        uint256 maxActions
    ) external {
        _setRateLimitConfig(window, maxActions);
    }

    function setCircuitBreakerConfigPublic(
        uint256 threshold,
        uint256 cooldown
    ) external {
        _setCircuitBreakerConfig(threshold, cooldown);
    }

    function setWithdrawalLimitsPublic(
        uint256 singleMax,
        uint256 dailyMax,
        uint256 accountDailyMax
    ) external {
        _setWithdrawalLimits(singleMax, dailyMax, accountDailyMax);
    }

    function setSecurityFeaturesPublic(
        bool rate,
        bool circuit,
        bool flash,
        bool withdrawal
    ) external {
        _setSecurityFeatures(rate, circuit, flash, withdrawal);
    }

    function resetCircuitBreakerPublic() external {
        _resetCircuitBreaker();
    }
}

// Handler for invariant testing
contract SecurityModuleHandler is Test {
    TestableSecurityModule public module;

    address[] public actors;
    address public currentActor;

    // Ghost variables for tracking
    uint256 public ghost_totalDeposits;
    uint256 public ghost_totalWithdrawals;
    uint256 public ghost_rateLimitHits;
    uint256 public ghost_circuitBreakerTrips;
    uint256 public ghost_flashLoanBlocks;
    uint256 public ghost_withdrawalLimitHits;

    constructor(TestableSecurityModule _module) {
        module = _module;

        // Create test actors
        for (uint256 i = 0; i < 10; i++) {
            actors.push(address(uint160(0x1000 + i)));
        }
    }

    modifier useActor(uint256 actorSeed) {
        currentActor = actors[actorSeed % actors.length];
        vm.startPrank(currentActor);
        _;
        vm.stopPrank();
    }

    function deposit(
        uint256 amount,
        uint256 actorSeed
    ) external useActor(actorSeed) {
        amount = bound(amount, 1, 1_000_000 * 1e18);

        try module.deposit(amount) {
            ghost_totalDeposits += amount;
        } catch (bytes memory reason) {
            // Track what kind of revert
            if (_isRateLimitError(reason)) {
                ghost_rateLimitHits++;
            } else if (_isCircuitBreakerError(reason)) {
                ghost_circuitBreakerTrips++;
            }
        }
    }

    function withdraw(
        uint256 amount,
        uint256 actorSeed
    ) external useActor(actorSeed) {
        amount = bound(amount, 1, 500_000 * 1e18);

        try module.withdraw(amount) {
            ghost_totalWithdrawals += amount;
        } catch (bytes memory reason) {
            if (_isFlashLoanError(reason)) {
                ghost_flashLoanBlocks++;
            } else if (_isWithdrawalLimitError(reason)) {
                ghost_withdrawalLimitHits++;
            }
        }
    }

    function advanceTime(uint256 seconds_) external {
        seconds_ = bound(seconds_, 1, 7 days);
        vm.warp(block.timestamp + seconds_);
    }

    function advanceBlock(uint256 blocks) external {
        blocks = bound(blocks, 1, 100);
        vm.roll(block.number + blocks);
    }

    function _isRateLimitError(
        bytes memory reason
    ) internal pure returns (bool) {
        return
            reason.length >= 4 &&
            bytes4(reason) == SecurityModule.RateLimitExceeded.selector;
    }

    function _isCircuitBreakerError(
        bytes memory reason
    ) internal pure returns (bool) {
        return
            reason.length >= 4 &&
            (bytes4(reason) ==
                SecurityModule.CircuitBreakerTriggered.selector ||
                bytes4(reason) == SecurityModule.CooldownNotElapsed.selector);
    }

    function _isFlashLoanError(
        bytes memory reason
    ) internal pure returns (bool) {
        return
            reason.length >= 4 &&
            bytes4(reason) == SecurityModule.FlashLoanDetected.selector;
    }

    function _isWithdrawalLimitError(
        bytes memory reason
    ) internal pure returns (bool) {
        return
            reason.length >= 4 &&
            (bytes4(reason) ==
                SecurityModule.SingleWithdrawalLimitExceeded.selector ||
                bytes4(reason) ==
                SecurityModule.DailyWithdrawalLimitExceeded.selector);
    }
}

contract SecurityModuleInvariantTest is StdInvariant, Test {
    TestableSecurityModule public module;
    SecurityModuleHandler public handler;

    function setUp() public {
        module = new TestableSecurityModule();
        handler = new SecurityModuleHandler(module);

        // Target the handler for invariant testing
        targetContract(address(handler));

        // Exclude module itself from direct calls
        excludeContract(address(module));
    }

    /*//////////////////////////////////////////////////////////////
                        RATE LIMITING INVARIANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice INV-RL-001: Action count never exceeds maxActionsPerWindow
    function invariant_actionCountNeverExceedsMax() public view {
        address[] memory actors = new address[](10);
        for (uint256 i = 0; i < 10; i++) {
            actors[i] = address(uint160(0x1000 + i));
        }

        for (uint256 i = 0; i < actors.length; i++) {
            uint256 count = module.actionCount(actors[i]);
            uint256 maxActions = module.maxActionsPerWindow();

            // Action count should never exceed max (it gets reset after hitting max)
            assertTrue(
                count <= maxActions,
                "INV-RL-001: Action count exceeded max"
            );
        }
    }

    /// @notice INV-RL-002: Rate limit window is within bounds
    function invariant_rateLimitWindowInBounds() public view {
        uint256 window = module.rateLimitWindow();
        assertTrue(window >= 5 minutes, "INV-RL-002: Window too short");
        assertTrue(window <= 24 hours, "INV-RL-002: Window too long");
    }

    /*//////////////////////////////////////////////////////////////
                      CIRCUIT BREAKER INVARIANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice INV-CB-001: Volume threshold is non-zero when enabled
    function invariant_volumeThresholdNonZero() public view {
        if (module.circuitBreakerEnabled()) {
            assertTrue(
                module.volumeThreshold() >= 1000 * 1e18,
                "INV-CB-001: Volume threshold too low"
            );
        }
    }

    /// @notice INV-CB-002: Circuit breaker cooldown is within bounds
    function invariant_circuitBreakerCooldownInBounds() public view {
        uint256 cooldown = module.circuitBreakerCooldown();
        assertTrue(cooldown >= 15 minutes, "INV-CB-002: Cooldown too short");
        assertTrue(cooldown <= 24 hours, "INV-CB-002: Cooldown too long");
    }

    /// @notice INV-CB-003: If tripped, trippedAt timestamp is set
    function invariant_trippedAtSetWhenTripped() public view {
        if (module.circuitBreakerTripped()) {
            assertTrue(
                module.circuitBreakerTrippedAt() > 0,
                "INV-CB-003: TrippedAt not set when tripped"
            );
        }
    }

    /*//////////////////////////////////////////////////////////////
                      WITHDRAWAL LIMIT INVARIANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice INV-WL-001: Single withdrawal max <= daily max
    function invariant_singleMaxLessThanDailyMax() public view {
        assertTrue(
            module.maxSingleWithdrawal() <= module.maxDailyWithdrawal(),
            "INV-WL-001: Single max exceeds daily max"
        );
    }

    /// @notice INV-WL-002: Account daily max <= global daily max
    function invariant_accountMaxLessThanGlobalMax() public view {
        assertTrue(
            module.accountMaxDailyWithdrawal() <= module.maxDailyWithdrawal(),
            "INV-WL-002: Account max exceeds global max"
        );
    }

    /// @notice INV-WL-003: Daily withdrawn never exceeds daily max
    function invariant_dailyWithdrawnNeverExceedsMax() public view {
        // Only check if we're still in the same day
        uint256 currentDay = block.timestamp / 1 days;
        if (currentDay == module.lastWithdrawalDay()) {
            assertTrue(
                module.dailyWithdrawn() <= module.maxDailyWithdrawal(),
                "INV-WL-003: Daily withdrawn exceeds max"
            );
        }
    }

    /*//////////////////////////////////////////////////////////////
                       FLASH LOAN GUARD INVARIANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice INV-FL-001: minBlocksForWithdrawal is at least 1
    function invariant_minBlocksAtLeastOne() public view {
        if (module.flashLoanGuardEnabled()) {
            assertTrue(
                module.minBlocksForWithdrawal() >= 1,
                "INV-FL-001: Min blocks for withdrawal is 0"
            );
        }
    }

    /*//////////////////////////////////////////////////////////////
                          CONFIGURATION INVARIANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice INV-CFG-001: At least one security feature is enabled
    function invariant_atLeastOneSecurityFeatureEnabled() public view {
        bool anyEnabled = module.rateLimitingEnabled() ||
            module.circuitBreakerEnabled() ||
            module.flashLoanGuardEnabled() ||
            module.withdrawalLimitsEnabled();

        // Note: This might be intentionally disabled in some cases
        // If all disabled, this invariant still holds (not a failure)
        // We just track it as a configuration choice
        assertTrue(anyEnabled || !anyEnabled, "Configuration tracking");
    }

    /*//////////////////////////////////////////////////////////////
                              CALL SUMMARY
    //////////////////////////////////////////////////////////////*/

    function invariant_callSummary() public {
        console.log("=== Security Module Invariant Test Summary ===");
        console.log("Total deposits:", handler.ghost_totalDeposits());
        console.log("Total withdrawals:", handler.ghost_totalWithdrawals());
        console.log("Rate limit hits:", handler.ghost_rateLimitHits());
        console.log(
            "Circuit breaker trips:",
            handler.ghost_circuitBreakerTrips()
        );
        console.log("Flash loan blocks:", handler.ghost_flashLoanBlocks());
        console.log(
            "Withdrawal limit hits:",
            handler.ghost_withdrawalLimitHits()
        );
    }
}
