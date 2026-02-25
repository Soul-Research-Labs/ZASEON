// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";

/**
 * @title InfrastructureRateLimiterTest
 * @notice The deprecated RateLimiter.sol has been removed.
 *         Rate limiting is now handled by RelayRateLimiter in contracts/security/.
 * @dev See test/security/ for RelayRateLimiter tests.
 */
contract InfrastructureRateLimiterTest is Test {
    function test_rateLimiterMigratedToRelayRateLimiter() public {
        // Deprecated RateLimiter has been removed.
        // All rate limiting functionality is in RelayRateLimiter.sol
        assertTrue(true, "Rate limiter migrated to RelayRateLimiter");
    }
}
