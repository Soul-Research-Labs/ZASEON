// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title MockWrappedCANTON
 * @notice Mock wCANTON token for testing the Canton bridge adapter
 * @dev Uses 6 decimals matching CANTON's native microcanton precision (1 CANTON = 1e6 microcanton)
 */
contract MockWrappedCANTON is ERC20, Ownable {
    uint8 private constant _DECIMALS = 6;

    constructor() ERC20("Wrapped CANTON", "wCANTON") Ownable(msg.sender) {}

    function decimals() public pure override returns (uint8) {
        return _DECIMALS;
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }

    function burn(uint256 amount) external {
        _burn(msg.sender, amount);
    }

    function burnFrom(address account, uint256 amount) external {
        _burn(account, amount);
    }
}
