// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title MockWrappedAPT
 * @notice Mock ERC-20 token representing wrapped APT for testing
 * @dev 8 decimals matching Aptos Octas precision (1 APT = 1e8 Octas)
 */
contract MockWrappedAPT is ERC20, Ownable {
    constructor() ERC20("Wrapped APT", "wAPT") Ownable(msg.sender) {}

    function decimals() public pure override returns (uint8) {
        return 8;
    }

    function mint(address to, uint256 amount) external onlyOwner {
        _mint(to, amount);
    }

    function burn(uint256 amount) external {
        _burn(msg.sender, amount);
    }

    function burnFrom(address from, uint256 amount) external {
        _spendAllowance(from, msg.sender, amount);
        _burn(from, amount);
    }
}
