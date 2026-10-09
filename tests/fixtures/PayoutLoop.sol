# SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

contract PayoutLoop {
    address[] public payees;

    function payAll() external {
        for (uint256 i = 0; i < payees.length; i++) {
            (bool ok,) = payees[i].call{value: 1}("");
            require(ok);
        }
    }
}
