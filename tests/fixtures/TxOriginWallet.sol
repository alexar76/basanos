# SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

contract TxOriginWallet {
    address public owner;

    constructor() {
        owner = tx.origin;
    }

    function pull() external {
        require(tx.origin == owner, "auth");
        payable(owner).transfer(address(this).balance);
    }
}
