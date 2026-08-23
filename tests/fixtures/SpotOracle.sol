# SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

contract SpotOracle {
    function price(address pool) external view returns (uint256) {
        (uint112 r0, uint112 r1, ) = IPair(pool).getReserves();
        return uint256(r1) * 1e18 / uint256(r0);
    }
}

interface IPair {
    function getReserves() external view returns (uint112, uint112, uint32);
}
