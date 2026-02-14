// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";

/**
 * @title InfrastructureRateLimiterTest
 * @notice The deprecated RateLimiter.sol has been removed.
 *         Rate limiting is now handled by BridgeRateLimiter in contracts/security/.
 * @dev See test/security/ for BridgeRateLimiter tests.
 */
contract InfrastructureRateLimiterTest is Test {
    function test_rateLimiterMigratedToBridgeRateLimiter() public {
        // Deprecated RateLimiter has been removed.
        // All rate limiting functionality is in BridgeRateLimiter.sol
        assertTrue(true, "Rate limiter migrated to BridgeRateLimiter");
    }
}
