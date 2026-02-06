// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Burnable.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";

/**
 * @title MockWrappedBNB
 * @notice Mock ERC-20 token representing wrapped BNB (wBNB) for testing
 * @dev 18 decimals to match BNB's wei granularity (1 BNB = 1e18 wei)
 *      Includes mint/burn for bridge adapter integration testing
 */
contract MockWrappedBNB is ERC20, ERC20Burnable, AccessControl {
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");

    constructor(address admin) ERC20("Wrapped BNB", "wBNB") {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(MINTER_ROLE, admin);
        // Pre-mint 10,000 wBNB to admin for testing
        _mint(admin, 10_000 * 10 ** 18);
    }

    /// @notice Mint wBNB (bridge adapter calls this on deposit completion)
    function mint(address to, uint256 amount) external onlyRole(MINTER_ROLE) {
        _mint(to, amount);
    }

    /// @notice Burn wBNB (bridge adapter calls this on withdrawal)
    function burn(uint256 amount) public override {
        super.burn(amount);
    }

    /// @notice Grant minter role to bridge adapter
    function grantMinter(address minter) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _grantRole(MINTER_ROLE, minter);
    }
}
