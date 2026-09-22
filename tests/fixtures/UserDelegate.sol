# SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

contract UserDelegate {
    function run(address target, bytes memory data) external {
        target.delegatecall(data);
    }
}
