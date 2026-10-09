# SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

contract PackedHash {
    function id(string memory a, string memory b) external pure returns (bytes32) {
        return keccak256(abi.encodePacked(a, b));
    }
}
