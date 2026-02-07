// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title MockWrappedOP
 * @notice Mock wrapped OP token for testing
 */
contract MockWrappedOP is ERC20, Ownable {
    constructor() ERC20("Wrapped Optimism", "wOP") Ownable(msg.sender) {}

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}
