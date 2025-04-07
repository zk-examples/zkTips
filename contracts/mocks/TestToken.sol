// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract TestToken is ERC20 {
    constructor(address user1, address user2) ERC20("TestToken", "TST") {
        _mint(user1, 1000 * 10 ** decimals());
        _mint(user2, 1000 * 10 ** decimals());
    }
}
