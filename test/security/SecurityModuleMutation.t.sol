// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../contracts/security/SecurityModule.sol";

contract SecurityHarness is SecurityModule {
    function checkRateLimit() public rateLimited {}

    function checkCircuitBreaker(uint256 val) public circuitBreaker(val) {}

    function checkFlashLoan() public noFlashLoan {}

    function checkWithdrawalLimit(uint256 amt) public withdrawalLimited(amt) {}

    // Admin functions to configure external to child
    function setRateLimit(uint256 window, uint256 max) public {
        _setRateLimitConfig(window, max);
    }

    function setCircuitBreaker(uint256 threshold, uint256 cooldown) public {
        _setCircuitBreakerConfig(threshold, cooldown);
    }

    function setFeatures(bool rl, bool cb, bool fl, bool wl) public {
        _setSecurityFeatures(rl, cb, fl, wl);
    }

    function setWithdrawalLimits(
        uint256 maxSingle,
        uint256 maxDaily,
        uint256 maxAccount
    ) public {
        _setWithdrawalLimits(maxSingle, maxDaily, maxAccount);
    }
}

contract SecurityModuleMutationTest is Test {
    SecurityHarness public harness;

    // Default limits for testing
    uint256 constant MAX_SINGLE_WITHDRAWAL = 100_000 ether;
    uint256 constant MAX_DAILY_WITHDRAWAL = 1_000_000 ether;
    uint256 constant MAX_ACCOUNT_DAILY = 100_000 ether;

    function setUp() public {
        harness = new SecurityHarness();
        harness.setFeatures(true, true, true, true);
        harness.setRateLimit(1 hours, 5);
        harness.setCircuitBreaker(1000 ether, 1 hours);
        harness.setWithdrawalLimits(
            MAX_SINGLE_WITHDRAWAL,
            MAX_DAILY_WITHDRAWAL,
            MAX_ACCOUNT_DAILY
        );
    }

    /**
     * @notice Fuzz test: withdrawal limit enforcement (bounded inputs)
     */
    function testFuzz_WithdrawalLimit(uint256 amt) public {
        // Bound to reasonable range that should pass
        amt = bound(amt, 0, MAX_SINGLE_WITHDRAWAL);
        harness.checkWithdrawalLimit(amt);
    }

    /**
     * @notice Fuzz test: circuit breaker enforcement (bounded inputs)
     */
    function testFuzz_CircuitBreaker(uint256 val) public {
        // Bound to reasonable range that shouldn't trigger circuit breaker
        val = bound(val, 0, 999 ether); // Below 1000 ether threshold
        harness.checkCircuitBreaker(val);
    }

    /**
     * @notice Test if rate limiting works
     */
    function test_RateLimiting() public {
        for (uint256 i = 0; i < 5; i++) {
            harness.checkRateLimit();
        }
        vm.expectRevert();
        harness.checkRateLimit();
    }

    /**
     * @notice Test circuit breaker trips on volume and blocks subsequent calls
     * @dev BUG FIX VERIFICATION: Previously the circuit breaker set state then reverted,
     *      which rolled back the state change. Now the threshold-exceeding tx succeeds
     *      (trips the breaker), and subsequent calls revert with CooldownNotElapsed.
     */
    function test_CircuitBreaker() public {
        // This exceeds the 1000 ether threshold — the tx should SUCCEED
        // but trip the circuit breaker for future calls
        harness.checkCircuitBreaker(1001 ether);

        // The circuit breaker is now tripped — this call should REVERT with CooldownNotElapsed
        vm.expectRevert();
        harness.checkCircuitBreaker(1 ether);

        // After cooldown elapses, calls should succeed again
        vm.warp(block.timestamp + 1 hours + 1);
        harness.checkCircuitBreaker(1 ether);
    }
}
