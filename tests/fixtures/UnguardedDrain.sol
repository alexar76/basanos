# SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

contract UnguardedDrain {
    mapping(address => uint256) public balances;

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        (bool ok, ) = msg.sender.call{value: amount}("");
        balances[msg.sender] = 0;
        require(ok, "pay");
    }
}
