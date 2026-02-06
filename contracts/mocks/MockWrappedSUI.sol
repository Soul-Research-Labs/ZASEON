// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title MockWrappedSUI
 * @notice Mock wSUI token for testing (9 decimals matching MIST precision)
 */
contract MockWrappedSUI is ERC20, Ownable {
    constructor() ERC20("Wrapped SUI", "wSUI") Ownable(msg.sender) {}

    function decimals() public pure override returns (uint8) {
        return 9;
    }

    function mint(address to, uint256 amount) external onlyOwner {
        _mint(to, amount);
    }

    function burn(uint256 amount) external {
        _burn(msg.sender, amount);
    }

    function burnFrom(address account, uint256 amount) external {
        _spendAllowance(account, msg.sender, amount);
        _burn(account, amount);
    }
}
