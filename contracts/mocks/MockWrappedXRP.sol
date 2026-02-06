// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Burnable.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";

/**
 * @title MockWrappedXRP
 * @notice Mock ERC-20 token representing wrapped XRP (wXRP) for testing
 * @dev 6 decimals to match XRP's drop granularity (1 XRP = 1,000,000 drops)
 *      Includes mint/burn for bridge adapter integration testing
 */
contract MockWrappedXRP is ERC20, ERC20Burnable, AccessControl {
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");

    uint8 private constant WXRP_DECIMALS = 6;

    constructor(address admin) ERC20("Wrapped XRP", "wXRP") {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(MINTER_ROLE, admin);
        // Pre-mint 100M wXRP to admin for testing
        _mint(admin, 100_000_000 * 10 ** WXRP_DECIMALS);
    }

    function decimals() public pure override returns (uint8) {
        return WXRP_DECIMALS;
    }

    /// @notice Mint wXRP (bridge adapter calls this on deposit completion)
    function mint(address to, uint256 amount) external onlyRole(MINTER_ROLE) {
        _mint(to, amount);
    }

    /// @notice Burn wXRP (bridge adapter calls this on withdrawal)
    function burn(uint256 amount) public override {
        super.burn(amount);
    }

    /// @notice Grant minter role to bridge adapter
    function grantMinter(address minter) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _grantRole(MINTER_ROLE, minter);
    }
}
