# SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

contract UnguardedMint {
    mapping(address => uint256) public balances;

    function mint(address to, uint256 amount) external {
        balances[to] += amount;
    }
}
